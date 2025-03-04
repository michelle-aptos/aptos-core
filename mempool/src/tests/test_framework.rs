// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::{
    core_mempool::CoreMempool,
    network::{MempoolNetworkEvents, MempoolNetworkSender, MempoolSyncMsg},
    shared_mempool::{start_shared_mempool, types::MultiBatchId},
    tests::{common, common::TestTransaction},
    MempoolClientRequest, MempoolClientSender, QuorumStoreRequest,
};
use aptos_channels::{aptos_channel, message_queues::QueueStyle};
use aptos_config::{
    config::NodeConfig,
    network_id::{NetworkId, PeerNetworkId},
};
use aptos_event_notifications::{ReconfigNotification, ReconfigNotificationListener};
use aptos_id_generator::U32IdGenerator;
use aptos_infallible::{Mutex, RwLock};
use aptos_mempool_notifications::MempoolNotifier;
use aptos_network::{
    application::storage::PeerMetadataStorage,
    peer_manager::{PeerManagerNotification, PeerManagerRequest},
    protocols::{direct_send::Message, rpc::InboundRpcRequest},
    testutils::{
        builder::TestFrameworkBuilder,
        test_framework::{setup_node_networks, TestFramework},
        test_node::{
            ApplicationNetworkHandle, ApplicationNode, InboundNetworkHandle, NodeId,
            OutboundMessageReceiver, TestNode,
        },
    },
    ProtocolId,
};
use aptos_storage_interface::mock::MockDbReaderWriter;
use aptos_types::{
    account_address::AccountAddress, mempool_status::MempoolStatusCode,
    on_chain_config::OnChainConfigPayload, transaction::SignedTransaction,
};
use aptos_vm_validator::mocks::mock_vm_validator::MockVMValidator;
use futures::{channel::oneshot, SinkExt};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::{runtime::Handle, time::Duration};
use tokio_stream::StreamExt;

/// An individual mempool node that runs in it's own runtime.
///
/// TODO: Add ability to mock StateSync updates to remove transactions
/// TODO: Add ability to reject transactions via Consensus
pub struct MempoolNode {
    /// The [`CoreMempool`] storage of the node
    pub mempool: Arc<Mutex<CoreMempool>>,
    /// A generator for [`MempoolSyncMsg`] request ids.
    pub request_id_generator: U32IdGenerator,

    // Mempool specific channels
    /// Used for incoming JSON-RPC requests (e.g. adding new transactions)
    pub mempool_client_sender: MempoolClientSender,
    /// Used for quorum store requests
    pub consensus_to_mempool_sender: futures::channel::mpsc::Sender<QuorumStoreRequest>,
    /// Used for StateSync commit notifications
    pub mempool_notifications: MempoolNotifier,

    // Networking specifics
    node_id: NodeId,
    peer_network_ids: HashMap<NetworkId, PeerNetworkId>,
    peer_metadata_storage: Arc<PeerMetadataStorage>,

    inbound_handles: HashMap<NetworkId, InboundNetworkHandle>,
    outbound_handles: HashMap<NetworkId, OutboundMessageReceiver>,
    other_inbound_handles: HashMap<PeerNetworkId, InboundNetworkHandle>,
}

impl std::fmt::Display for MempoolNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.node_id)
    }
}

impl ApplicationNode for MempoolNode {
    fn node_id(&self) -> NodeId {
        self.node_id
    }

    fn default_protocols(&self) -> &[ProtocolId] {
        &[ProtocolId::MempoolDirectSend]
    }

    fn get_inbound_handle(&self, network_id: NetworkId) -> InboundNetworkHandle {
        self.inbound_handles
            .get(&network_id)
            .unwrap_or_else(|| panic!("Must have inbound handle for network {}", network_id))
            .clone()
    }

    fn add_inbound_handle_for_peer(
        &mut self,
        peer_network_id: PeerNetworkId,
        handle: InboundNetworkHandle,
    ) {
        if self
            .other_inbound_handles
            .insert(peer_network_id, handle)
            .is_some()
        {
            panic!(
                "Double added handle for {} on {}",
                peer_network_id, self.node_id
            )
        }
    }

    fn get_inbound_handle_for_peer(&self, peer_network_id: PeerNetworkId) -> InboundNetworkHandle {
        self.other_inbound_handles
            .get(&peer_network_id)
            .expect("Must have inbound handle for other peer")
            .clone()
    }

    fn get_outbound_handle(&mut self, network_id: NetworkId) -> &mut OutboundMessageReceiver {
        self.outbound_handles.get_mut(&network_id).unwrap()
    }

    fn get_peer_metadata_storage(&self) -> &PeerMetadataStorage {
        &self.peer_metadata_storage
    }

    fn peer_network_ids(&self) -> &HashMap<NetworkId, PeerNetworkId> {
        &self.peer_network_ids
    }
}

impl MempoolNode {
    /// Queues transactions for sending on a node, uses client
    pub async fn add_txns_via_client(&mut self, txns: &[TestTransaction]) {
        for txn in sign_transactions(txns) {
            let (sender, receiver) = oneshot::channel();

            self.mempool_client_sender
                .send(MempoolClientRequest::SubmitTransaction(txn, sender))
                .await
                .unwrap();
            let status = receiver.await.unwrap().unwrap();
            assert_eq!(status.0.code, MempoolStatusCode::Accepted)
        }
    }

    pub async fn commit_txns(&mut self, txns: &[TestTransaction]) {
        for txn in sign_transactions(txns) {
            self.mempool
                .lock()
                .commit_transaction(&txn.sender(), txn.sequence_number());
        }
    }

    /// Asynchronously waits for up to 1 second for txns to appear in mempool
    pub async fn wait_on_txns_in_mempool(&self, txns: &[TestTransaction]) {
        for _ in 0..10 {
            let block = self.mempool.lock().get_batch(100, 102400, HashSet::new());

            if block_contains_all_transactions(&block, txns) {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await
        }
    }

    pub fn assert_only_txns_in_mempool(&self, txns: &[TestTransaction]) {
        if let Err((actual, expected)) =
            self.assert_condition_on_mempool_txns(txns, block_only_contains_transactions)
        {
            panic!(
                "Expected to contain test transactions {:?}, but got {:?}",
                expected, actual
            );
        }
    }

    pub fn assert_txns_in_mempool(&self, txns: &[TestTransaction]) {
        if let Err((actual, expected)) =
            self.assert_condition_on_mempool_txns(txns, block_contains_all_transactions)
        {
            panic!(
                "Expected to contain test transactions {:?}, but got {:?}",
                expected, actual
            );
        }
    }

    pub fn assert_txns_not_in_mempool(&self, txns: &[TestTransaction]) {
        if let Err((actual, expected)) = self.assert_condition_on_mempool_txns(txns, {
            |actual, expected| !block_contains_any_transaction(actual, expected)
        }) {
            panic!(
                "Expected to not contain test transactions {:?}, but got {:?}",
                expected, actual
            );
        }
    }

    fn assert_condition_on_mempool_txns<
        Condition: FnOnce(&[SignedTransaction], &[TestTransaction]) -> bool,
    >(
        &self,
        txns: &[TestTransaction],
        condition: Condition,
    ) -> Result<(), (Vec<(AccountAddress, u64)>, Vec<(AccountAddress, u64)>)> {
        let block = self.mempool.lock().get_batch(100, 102400, HashSet::new());
        if !condition(&block, txns) {
            let actual: Vec<_> = block
                .iter()
                .map(|txn| (txn.sender(), txn.sequence_number()))
                .collect();
            let expected: Vec<_> = txns
                .iter()
                .map(|txn| {
                    (
                        TestTransaction::get_address(txn.address),
                        txn.sequence_number,
                    )
                })
                .collect();
            Err((actual, expected))
        } else {
            Ok(())
        }
    }

    pub async fn receive_message(
        &mut self,
        protocol_id: ProtocolId,
        remote_peer_network_id: PeerNetworkId,
        txns: &[TestTransaction],
    ) {
        let network_id = remote_peer_network_id.network_id();
        let remote_peer_id = remote_peer_network_id.peer_id();
        let inbound_handle = self.get_inbound_handle(network_id);
        let batch_id = MultiBatchId::from_timeline_ids(&vec![1].into(), &vec![10].into());
        let msg = MempoolSyncMsg::BroadcastTransactionsRequest {
            request_id: batch_id.clone(),
            transactions: sign_transactions(txns),
        };
        let data = protocol_id.to_bytes(&msg).unwrap().into();
        let (notif, maybe_receiver) = match protocol_id {
            ProtocolId::MempoolDirectSend => (
                PeerManagerNotification::RecvMessage(remote_peer_id, Message {
                    protocol_id,
                    mdata: data,
                }),
                None,
            ),
            ProtocolId::MempoolRpc => {
                let (res_tx, res_rx) = oneshot::channel();
                let notif = PeerManagerNotification::RecvRpc(remote_peer_id, InboundRpcRequest {
                    protocol_id,
                    data,
                    res_tx,
                });
                (notif, Some(res_rx))
            },
            _ => panic!("Invalid protocol"),
        };
        inbound_handle
            .inbound_message_sender
            .push((remote_peer_id, protocol_id), notif)
            .unwrap();

        let response: MempoolSyncMsg = if let Some(res_rx) = maybe_receiver {
            let response = res_rx.await.unwrap().unwrap();
            protocol_id.from_bytes(&response).unwrap()
        } else {
            match self.get_outbound_handle(network_id).next().await.unwrap() {
                PeerManagerRequest::SendDirectSend(peer_id, msg) => {
                    assert_eq!(peer_id, remote_peer_id);
                    msg.protocol_id.from_bytes(&msg.mdata).unwrap()
                },
                _ => panic!("Should not be getting an RPC response"),
            }
        };
        if let MempoolSyncMsg::BroadcastTransactionsResponse {
            request_id,
            retry,
            backoff,
        } = response
        {
            assert_eq!(batch_id, request_id);
            assert!(!retry);
            assert!(!backoff);
        } else {
            panic!("Expected a response!");
        }
    }

    pub async fn send_broadcast_and_receive_ack(
        &mut self,
        expected_peer_network_id: PeerNetworkId,
        expected_txns: &[TestTransaction],
    ) {
        self.send_broadcast_and_receive_response(
            expected_peer_network_id,
            expected_txns,
            false,
            false,
        )
        .await
    }

    pub async fn send_broadcast_and_receive_retry(
        &mut self,
        expected_peer_network_id: PeerNetworkId,
        expected_txns: &[TestTransaction],
    ) {
        // Don't backoff so the test is faster
        self.send_broadcast_and_receive_response(
            expected_peer_network_id,
            expected_txns,
            true,
            false,
        )
        .await
    }

    /// Send a broadcast and receive a response
    async fn send_broadcast_and_receive_response(
        &mut self,
        expected_peer_network_id: PeerNetworkId,
        expected_txns: &[TestTransaction],
        retry: bool,
        backoff: bool,
    ) {
        let network_id = expected_peer_network_id.network_id();
        let expected_peer_id = expected_peer_network_id.peer_id();
        let inbound_handle = self.get_inbound_handle(network_id);
        let message = self.get_next_network_msg(network_id).await;
        let (peer_id, protocol_id, data, maybe_rpc_sender) = match message {
            PeerManagerRequest::SendRpc(peer_id, msg) => {
                (peer_id, msg.protocol_id, msg.data, Some(msg.res_tx))
            },
            PeerManagerRequest::SendDirectSend(peer_id, msg) => {
                (peer_id, msg.protocol_id, msg.mdata, None)
            },
        };
        assert_eq!(peer_id, expected_peer_id);
        let mempool_message = common::decompress_and_deserialize(&data.to_vec());
        let request_id = match mempool_message {
            MempoolSyncMsg::BroadcastTransactionsRequest {
                request_id,
                transactions,
            } => {
                if !block_only_contains_transactions(&transactions, expected_txns) {
                    let txns: Vec<_> = transactions
                        .iter()
                        .map(|txn| (txn.sender(), txn.sequence_number()))
                        .collect();
                    let expected_txns: Vec<_> = expected_txns
                        .iter()
                        .map(|txn| {
                            (
                                TestTransaction::get_address(txn.address),
                                txn.sequence_number,
                            )
                        })
                        .collect();

                    panic!(
                        "Request doesn't match. Actual: {:?} Expected: {:?}",
                        txns, expected_txns
                    );
                }
                request_id
            },
            MempoolSyncMsg::BroadcastTransactionsResponse { .. } => {
                panic!("We aren't supposed to be getting as response here");
            },
        };
        let response = MempoolSyncMsg::BroadcastTransactionsResponse {
            request_id,
            retry,
            backoff,
        };
        let bytes = protocol_id.to_bytes(&response).unwrap();

        if let Some(rpc_sender) = maybe_rpc_sender {
            rpc_sender.send(Ok(bytes.into())).unwrap();
        } else {
            let notif = PeerManagerNotification::RecvMessage(peer_id, Message {
                protocol_id,
                mdata: bytes.into(),
            });
            inbound_handle
                .inbound_message_sender
                .push((peer_id, protocol_id), notif)
                .unwrap();
        }
    }
}

impl TestNode for MempoolNode {}

pub type MempoolTestFrameworkBuilder = TestFrameworkBuilder<MempoolTestFramework, MempoolNode>;

/// A [`TestFramework`] for [`MempoolNode`]s to test Mempool in a single and multi-node mock network
/// environment.
pub struct MempoolTestFramework {
    pub nodes: HashMap<NodeId, MempoolNode>,
}

impl TestFramework<MempoolNode> for MempoolTestFramework {
    fn new(nodes: HashMap<NodeId, MempoolNode>) -> Self {
        Self { nodes }
    }

    fn build_node(
        node_id: NodeId,
        config: NodeConfig,
        peer_network_ids: &[PeerNetworkId],
    ) -> MempoolNode {
        // Collect mappings of network_id to peer_network_id
        let mut network_ids = Vec::new();
        let mut network_id_mapping = HashMap::new();
        for peer_network_id in peer_network_ids {
            let network_id = peer_network_id.network_id();
            assert!(
                !network_id_mapping.contains_key(&network_id),
                "Duplicate network id for node"
            );
            network_ids.push(network_id);
            network_id_mapping.insert(network_id, *peer_network_id);
        }

        let (application_handles, inbound_handles, outbound_handles, peer_metadata_storage) =
            setup_node_networks(&network_ids);
        let (mempool_client_sender, consensus_to_mempool_sender, mempool_notifications, mempool) =
            setup_mempool(config, application_handles, peer_metadata_storage.clone());

        MempoolNode {
            node_id,
            peer_network_ids: network_id_mapping,
            mempool,
            mempool_client_sender,
            consensus_to_mempool_sender,
            mempool_notifications,
            inbound_handles,
            outbound_handles,
            other_inbound_handles: HashMap::new(),
            peer_metadata_storage,
            request_id_generator: U32IdGenerator::new(),
        }
    }

    fn take_node(&mut self, node_id: NodeId) -> MempoolNode {
        self.nodes.remove(&node_id).expect("Node must exist")
    }
}

/// Creates a full [`SharedMempool`] and mocks all of the database information.
///
/// This hooks in the [`ApplicationNetworkHandle`]s into mempool so that the requests make it all
/// the way to the [`SharedMempool`]
fn setup_mempool(
    config: NodeConfig,
    network_handles: Vec<ApplicationNetworkHandle<MempoolNetworkSender, MempoolNetworkEvents>>,
    peer_metadata_storage: Arc<PeerMetadataStorage>,
) -> (
    MempoolClientSender,
    futures::channel::mpsc::Sender<QuorumStoreRequest>,
    MempoolNotifier,
    Arc<Mutex<CoreMempool>>,
) {
    let (sender, _subscriber) = futures::channel::mpsc::unbounded();
    let (ac_endpoint_sender, ac_endpoint_receiver) = mpsc_channel();
    let (quorum_store_sender, quorum_store_receiver) = mpsc_channel();
    let (mempool_notifier, mempool_listener) =
        aptos_mempool_notifications::new_mempool_notifier_listener_pair();

    let mempool = Arc::new(Mutex::new(CoreMempool::new(&config)));
    let vm_validator = Arc::new(RwLock::new(MockVMValidator));
    let db_ro = Arc::new(MockDbReaderWriter);

    let (reconfig_sender, reconfig_events) = aptos_channel::new(QueueStyle::LIFO, 1, None);
    let reconfig_event_subscriber = ReconfigNotificationListener {
        notification_receiver: reconfig_events,
    };
    reconfig_sender
        .push((), ReconfigNotification {
            version: 1,
            on_chain_configs: OnChainConfigPayload::new(1, Arc::new(HashMap::new())),
        })
        .unwrap();

    start_shared_mempool(
        &Handle::current(),
        &config,
        mempool.clone(),
        network_handles,
        ac_endpoint_receiver,
        quorum_store_receiver,
        mempool_listener,
        reconfig_event_subscriber,
        db_ro,
        vm_validator,
        vec![sender],
        peer_metadata_storage,
    );

    (
        ac_endpoint_sender,
        quorum_store_sender,
        mempool_notifier,
        mempool,
    )
}

fn mpsc_channel<T>() -> (
    futures::channel::mpsc::Sender<T>,
    futures::channel::mpsc::Receiver<T>,
) {
    futures::channel::mpsc::channel(1_024)
}

/// Creates a single [`TestTransaction`] with the given `seq_num`.
pub const fn test_transaction(seq_num: u64) -> TestTransaction {
    TestTransaction::new(1, seq_num, 1)
}

/// Tells us if a [`SignedTransaction`] block contains only the [`TestTransaction`]s
pub fn block_only_contains_transactions(
    block: &[SignedTransaction],
    txns: &[TestTransaction],
) -> bool {
    txns.iter()
        .all(|txn| block_contains_transaction(block, txn))
        && block.len() == txns.len()
}

/// Tells us if a [`SignedTransaction`] block contains all the [`TestTransaction`]s
pub fn block_contains_all_transactions(
    block: &[SignedTransaction],
    txns: &[TestTransaction],
) -> bool {
    txns.iter()
        .all(|txn| block_contains_transaction(block, txn))
}

/// Tells us if a [`SignedTransaction`] block contains any of the [`TestTransaction`]s
pub fn block_contains_any_transaction(
    block: &[SignedTransaction],
    txns: &[TestTransaction],
) -> bool {
    txns.iter()
        .any(|txn| block_contains_transaction(block, txn))
        && block.len() == txns.len()
}

/// Tells us if a [`SignedTransaction`] block contains the [`TestTransaction`]
fn block_contains_transaction(block: &[SignedTransaction], txn: &TestTransaction) -> bool {
    block.iter().any(|signed_txn| {
        signed_txn.sequence_number() == txn.sequence_number
            && signed_txn.sender() == TestTransaction::get_address(txn.address)
            && signed_txn.gas_unit_price() == txn.gas_price
    })
}

/// Signs [`TestTransaction`]s with a max gas amount
pub fn sign_transactions(txns: &[TestTransaction]) -> Vec<SignedTransaction> {
    txns.iter()
        .map(|txn| txn.make_signed_transaction_with_max_gas_amount(5))
        .collect()
}

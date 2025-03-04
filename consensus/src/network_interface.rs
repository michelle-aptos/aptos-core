// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

//! Interface between Consensus and Network layers.

use crate::{
    counters,
    quorum_store::types::{Batch, BatchRequest, Fragment},
};
use anyhow::anyhow;
use aptos_channels::{aptos_channel, message_queues::QueueStyle};
use aptos_config::network_id::{NetworkId, PeerNetworkId};
use aptos_consensus_types::{
    block_retrieval::{BlockRetrievalRequest, BlockRetrievalResponse},
    epoch_retrieval::EpochRetrievalRequest,
    experimental::{commit_decision::CommitDecision, commit_vote::CommitVote},
    proof_of_store::{ProofOfStore, SignedDigest},
    proposal_msg::ProposalMsg,
    sync_info::SyncInfo,
    vote_msg::VoteMsg,
};
use aptos_logger::prelude::*;
use aptos_network::{
    application::storage::PeerMetadataStorage,
    constants::NETWORK_CHANNEL_SIZE,
    error::NetworkError,
    peer_manager::{ConnectionRequestSender, PeerManagerRequestSender},
    protocols::{
        network::{
            AppConfig, ApplicationNetworkSender, NetworkEvents, NetworkSender, NewNetworkSender,
        },
        rpc::error::RpcError,
        wire::handshake::v1::ProtocolIdSet,
    },
    ProtocolId,
};
use aptos_types::{epoch_change::EpochChangeProof, PeerId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};

/// Network type for consensus
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ConsensusMsg {
    /// RPC to get a chain of block of the given length starting from the given block id.
    BlockRetrievalRequest(Box<BlockRetrievalRequest>),
    /// Carries the returned blocks and the retrieval status.
    BlockRetrievalResponse(Box<BlockRetrievalResponse>),
    /// Request to get a EpochChangeProof from current_epoch to target_epoch
    EpochRetrievalRequest(Box<EpochRetrievalRequest>),
    /// ProposalMsg contains the required information for the proposer election protocol to make
    /// its choice (typically depends on round and proposer info).
    ProposalMsg(Box<ProposalMsg>),
    /// This struct describes basic synchronization metadata.
    SyncInfo(Box<SyncInfo>),
    /// A vector of LedgerInfo with contiguous increasing epoch numbers to prove a sequence of
    /// epoch changes from the first LedgerInfo's epoch.
    EpochChangeProof(Box<EpochChangeProof>),
    /// VoteMsg is the struct that is ultimately sent by the voter in response for receiving a
    /// proposal.
    VoteMsg(Box<VoteMsg>),
    /// CommitProposal is the struct that is sent by the validator after execution to propose
    /// on the committed state hash root.
    CommitVoteMsg(Box<CommitVote>),
    /// CommitDecision is the struct that is sent by the validator after collecting no fewer
    /// than 2f + 1 signatures on the commit proposal. This part is not on the critical path, but
    /// it can save slow machines to quickly confirm the execution result.
    CommitDecisionMsg(Box<CommitDecision>),
    /// Quorum Store: Send a fragment -- a sequence of transactions that are part of an in-progress
    /// batch -- from the fragment generator to remote validators.
    FragmentMsg(Box<Fragment>),
    /// Quorum Store: Request the payloads of a completed batch.
    BatchRequestMsg(Box<BatchRequest>),
    /// Quorum Store: Respond with a completed batch's payload -- a sequence of transactions,
    /// identified by its digest.
    BatchMsg(Box<Batch>),
    /// Quorum Store: Send a signed batch digest. This is a vote for the batch and a promise that
    /// the batch of transactions was received and will be persisted until batch expiration.
    SignedDigestMsg(Box<SignedDigest>),
    /// Quorum Store: Broadcast a certified proof of store (a digest that received 2f+1 votes).
    ProofOfStoreMsg(Box<ProofOfStore>),
}

/// Network type for consensus
impl ConsensusMsg {
    /// ConsensusMsg type in string
    ///
    pub fn name(&self) -> &str {
        match self {
            ConsensusMsg::BlockRetrievalRequest(_) => "BlockRetrievalRequest",
            ConsensusMsg::BlockRetrievalResponse(_) => "BlockRetrievalResponse",
            ConsensusMsg::EpochRetrievalRequest(_) => "EpochRetrievalRequest",
            ConsensusMsg::ProposalMsg(_) => "ProposalMsg",
            ConsensusMsg::SyncInfo(_) => "SyncInfo",
            ConsensusMsg::EpochChangeProof(_) => "EpochChangeProof",
            ConsensusMsg::VoteMsg(_) => "VoteMsg",
            ConsensusMsg::CommitVoteMsg(_) => "CommitVoteMsg",
            ConsensusMsg::CommitDecisionMsg(_) => "CommitDecisionMsg",
            ConsensusMsg::FragmentMsg(_) => "FragmentMsg",
            ConsensusMsg::BatchRequestMsg(_) => "BatchRequestMsg",
            ConsensusMsg::BatchMsg(_) => "BatchMsg",
            ConsensusMsg::SignedDigestMsg(_) => "SignedDigestMsg",
            ConsensusMsg::ProofOfStoreMsg(_) => "ProofOfStoreMsg",
        }
    }
}

/// The interface from Network to Consensus layer.
///
/// `ConsensusNetworkEvents` is a `Stream` of `PeerManagerNotification` where the
/// raw `Bytes` direct-send and rpc messages are deserialized into
/// `ConsensusMessage` types. `ConsensusNetworkEvents` is a thin wrapper around
/// an `channel::Receiver<PeerManagerNotification>`.
pub type ConsensusNetworkEvents = NetworkEvents<ConsensusMsg>;

/// The interface from Consensus to Networking layer.
///
/// This is a thin wrapper around a `NetworkSender<ConsensusMsg>`, so it is easy
/// to clone and send off to a separate task. For example, the rpc requests
/// return Futures that encapsulate the whole flow, from sending the request to
/// remote, to finally receiving the response and deserializing. It therefore
/// makes the most sense to make the rpc call on a separate async task, which
/// requires the `ConsensusNetworkSender` to be `Clone` and `Send`.
#[derive(Clone)]
pub struct ConsensusNetworkSender {
    network_sender: NetworkSender<ConsensusMsg>,
    peer_metadata_storage: Option<Arc<PeerMetadataStorage>>,
}

/// Supported protocols in preferred order (from highest priority to lowest).
pub const RPC: &[ProtocolId] = &[
    ProtocolId::ConsensusRpcCompressed,
    ProtocolId::ConsensusRpcBcs,
    ProtocolId::ConsensusRpcJson,
];
/// Supported protocols in preferred order (from highest priority to lowest).
pub const DIRECT_SEND: &[ProtocolId] = &[
    ProtocolId::ConsensusDirectSendCompressed,
    ProtocolId::ConsensusDirectSendBcs,
    ProtocolId::ConsensusDirectSendJson,
];

/// Configuration for the network endpoints to support consensus.
/// TODO: make this configurable
pub fn network_endpoint_config() -> AppConfig {
    let protos = RPC.iter().chain(DIRECT_SEND.iter()).copied();
    AppConfig::p2p(
        protos,
        aptos_channel::Config::new(NETWORK_CHANNEL_SIZE)
            .queue_style(QueueStyle::FIFO)
            .counters(&counters::PENDING_CONSENSUS_NETWORK_EVENTS),
    )
}

impl NewNetworkSender for ConsensusNetworkSender {
    fn new(
        peer_mgr_reqs_tx: PeerManagerRequestSender,
        connection_reqs_tx: ConnectionRequestSender,
    ) -> Self {
        Self {
            network_sender: NetworkSender::new(peer_mgr_reqs_tx, connection_reqs_tx),
            peer_metadata_storage: None,
        }
    }
}

impl ConsensusNetworkSender {
    /// Initialize a shared hashmap about connections metadata that is updated by the receiver.
    pub fn initialize(&mut self, peer_metadata_storage: Arc<PeerMetadataStorage>) {
        self.peer_metadata_storage = Some(peer_metadata_storage);
    }

    /// Query the supported protocols from this peer's connection.
    fn supported_protocols(&self, peer: PeerId) -> anyhow::Result<ProtocolIdSet> {
        if let Some(peer_metadata_storage) = &self.peer_metadata_storage {
            let peer_network_id = PeerNetworkId::new(NetworkId::Validator, peer);
            peer_metadata_storage
                .read(peer_network_id)
                .map(|peer_info| peer_info.active_connection.application_protocols)
                .ok_or_else(|| anyhow!("Peer not connected"))
        } else {
            Err(anyhow!("ConsensusNetworkSender not initialized"))
        }
    }

    /// Choose the overlapping protocol for peer. The local protocols are sorted from most to least preferred.
    fn preferred_protocol_for_peer(
        &self,
        peer: PeerId,
        local_protocols: &[ProtocolId],
    ) -> anyhow::Result<ProtocolId> {
        let remote_protocols = self.supported_protocols(peer)?;
        for protocol in local_protocols {
            if remote_protocols.contains(*protocol) {
                return Ok(*protocol);
            }
        }
        Err(anyhow!("No available protocols for peer {}", peer))
    }
}

#[async_trait]
impl ApplicationNetworkSender<ConsensusMsg> for ConsensusNetworkSender {
    /// Send a single message to the destination peer using the available ProtocolId.
    fn send_to(&self, recipient: PeerId, message: ConsensusMsg) -> Result<(), NetworkError> {
        let protocol = self.preferred_protocol_for_peer(recipient, DIRECT_SEND)?;
        self.network_sender.send_to(recipient, protocol, message)
    }

    /// Send a single message to the destination peers using the available ProtocolId.
    fn send_to_many(
        &self,
        recipients: impl Iterator<Item = PeerId>,
        message: ConsensusMsg,
    ) -> Result<(), NetworkError> {
        let mut peers_per_protocol = HashMap::new();
        let mut not_available = vec![];
        for peer in recipients {
            match self.preferred_protocol_for_peer(peer, DIRECT_SEND) {
                Ok(protocol) => peers_per_protocol
                    .entry(protocol)
                    .or_insert_with(Vec::new)
                    .push(peer),
                Err(_) => not_available.push(peer),
            }
        }
        if !not_available.is_empty() {
            sample!(
                SampleRate::Duration(Duration::from_secs(10)),
                warn!("Unavailable peers: {:?}", not_available)
            );
        }
        for (protocol, peers) in peers_per_protocol {
            self.network_sender
                .send_to_many(peers.into_iter(), protocol, message.clone())?;
        }
        Ok(())
    }

    /// Send a RPC to the destination peer using the available ProtocolId.
    async fn send_rpc(
        &self,
        recipient: PeerId,
        message: ConsensusMsg,
        timeout: Duration,
    ) -> Result<ConsensusMsg, RpcError> {
        let protocol = self.preferred_protocol_for_peer(recipient, RPC)?;
        self.network_sender
            .send_rpc(recipient, protocol, message, timeout)
            .await
    }
}

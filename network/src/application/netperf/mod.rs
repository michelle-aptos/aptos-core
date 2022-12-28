// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

//! Network Load Generator
//!
//! NetPerf is used to stress the network layer to gouge potential performance capabilities
//! and simplify network-related performance profiling and debugging
//!

use crate::application::storage::PeerMetadataStorage;
use crate::transport::ConnectionMetadata;
use crate::{
    application::netperf::interface::{NetPerfMsg::*, NetPerfNetworkEvents, NetPerfNetworkSender},
    constants::NETWORK_CHANNEL_SIZE,
    counters,
    error::NetworkError,
    logging::NetworkSchema,
    peer_manager::{ConnectionRequestSender, PeerManagerRequestSender},
    protocols::{
        network::{
            AppConfig, ApplicationNetworkSender, Event, NetworkEvents, NetworkSender,
            NewNetworkSender,
        },
        rpc::error::RpcError,
    },
    ProtocolId,
};
use aptos_channels::{aptos_channel, message_queues::QueueStyle};
use aptos_config::network_id::{NetworkContext, PeerNetworkId};
use aptos_logger::prelude::*;
use aptos_types::account_address::AccountAddress;
use aptos_types::network_address::ParseError::NetworkLayerMissing;
use aptos_types::PeerId;
use axum::{
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use dashmap::DashMap;
use futures::StreamExt;
use futures_util::stream::FuturesUnordered;
use serde::Serialize;
use std::fs::OpenOptions;
use std::{sync::Arc, time::Duration};
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender};

pub mod builder;
mod interface;

const NETPERF_COMMAND_CHANNEL_SIZE: usize = 1024;

pub struct NetPerf {
    network_context: NetworkContext,
    peers: Arc<PeerMetadataStorage>,
    peer_list: Arc<DashMap<PeerId, PeerNetPerfStat>>, //with capacity and hasher
    sender: Arc<NetPerfNetworkSender>,
    events: NetPerfNetworkEvents,
    netperf_port: u16,
}

struct PeerNetPerfStat {}

impl PeerNetPerfStat {
    pub fn new(_md: ConnectionMetadata) -> Self {
        PeerNetPerfStat {}
    }
}

#[derive(Clone)]
struct NetPerfState {
    peers: Arc<PeerMetadataStorage>, //TODO: DO I need this?
    peer_list: Arc<DashMap<PeerId, PeerNetPerfStat>>, //with capacity and hasher
    sender: Arc<NetPerfNetworkSender>,
    tx: Sender<NetPerfCommands>,
}

impl NetPerf {
    pub fn new(
        network_context: NetworkContext,
        peers: Arc<PeerMetadataStorage>,
        sender: Arc<NetPerfNetworkSender>,
        events: NetPerfNetworkEvents,
        netperf_port: u16,
    ) -> Self {
        NetPerf {
            network_context,
            peers,
            peer_list: Arc::new(DashMap::with_capacity(128)),
            sender,
            events,
            netperf_port,
        }
    }

    /// Configuration for the network endpoints to support NetPerf.
    pub fn network_endpoint_config() -> AppConfig {
        AppConfig::p2p(
            [ProtocolId::NetPerfRpcCompressed],
            aptos_channel::Config::new(NETWORK_CHANNEL_SIZE).queue_style(QueueStyle::FIFO),
        )
    }

    fn net_perf_state(&self, sender: Sender<NetPerfCommands>) -> NetPerfState {
        NetPerfState {
            peers: self.peers.clone(),
            sender: self.sender.clone(),
            peer_list: self.peer_list.clone(),
            tx: sender,
        }
    }

    async fn start(mut self) {
        let port = preferred_axum_port(self.netperf_port);
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<NetPerfCommands>(NETPERF_COMMAND_CHANNEL_SIZE);

        info!(
            NetworkSchema::new(&self.network_context),
            "{} NetPerf Event Listener started", self.network_context,
        );

        spawn_named!(
            "NetPerf Axum",
            start_axum(self.net_perf_state(tx.clone()), port)
        );
        spawn_named!(
            "NetPerf EventHandler",
            netperf_comp_handler(self.net_perf_state(tx.clone()), rx)
        );

        loop {
            futures::select! {
                maybe_event = self.events.next() => {
                    // Shutdown the NetPerf when this network instance shuts
                    // down. This happens when the `PeerManager` drops.
                    let event = match maybe_event {
                        Some(event) => event,
                        None => break,
                    };

                    match event {
                        Event::NewPeer(metadata) => {
                            self.peer_list.insert(
                                metadata.remote_peer_id,
                                PeerNetPerfStat::new(metadata)
                            );
                        }
                        Event::LostPeer(metadata) => {
                            self.peer_list.remove(
                                &metadata.remote_peer_id
                            );
                        }
                        _ => {/* Currently ignore all*/}
                    }
                }
            }
        }
        warn!(
            NetworkSchema::new(&self.network_context),
            "{} NetPerf event listener terminated", self.network_context
        );
    }
}
#[derive(Clone)]
enum NetPerfCommands {
    Broadcast,
}

fn preferred_axum_port(netperf_port: u16) -> u16 {
    if netperf_port != 9107 {
        let _ = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open("/tmp/9107.tmp");

        let _ = OpenOptions::new()
            .write(true)
            .create(true)
            .open(format!("/tmp/{}.tmp", netperf_port));
    }
    return netperf_port;
}

async fn start_axum(state: NetPerfState, netperf_port: u16) {
    let app = Router::new()
        .route("/", get(usage_handler))
        .route("/peers", get(get_peers).layer(Extension(state.clone())))
        .route(
            "/command",
            post(parse_query).layer(Extension(state.clone())),
        );

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], netperf_port));

    // run it with hyper on netperf_port
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn usage_handler() -> &'static str {
    "Usage: curl 127.0.0.01:9107/peers"
}

#[derive(Serialize)]
struct PeerList {
    len: usize,
    peers: Vec<PeerId>,
}

impl PeerList {
    pub fn new(len: usize) -> Self {
        PeerList {
            len,
            peers: Vec::with_capacity(len),
        }
    }
}

async fn get_peers(Extension(state): Extension<NetPerfState>) -> Json<PeerList> {
    let mut out = PeerList::new(state.peer_list.len());

    let connected = state.peer_list.iter();

    for peer in connected {
        out.peers.push(peer.key().to_owned());
    }

    Json(out)
}

async fn parse_query(
    Extension(state): Extension<NetPerfState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    spawn_named!("[NetPerf] Broadcast Task", netperf_broadcast(state.clone()));

    StatusCode::OK
}

async fn netperf_comp_handler(state: NetPerfState, mut rx: Receiver<NetPerfCommands>) {
    let mut rpc_handlers = FuturesUnordered::new();

    loop {
        tokio::select! {
            opt_cmd = rx.recv() => {
                match opt_cmd {
                    Some(cmd) => {
                        for peer in state.peer_list.iter() {
                            //TODO(AlexM): Yet another Alloc + Copy OPs.
                            // Best use Refs - Just ARC
                            rpc_handlers.push(state.sender.send_rpc(
                                peer.key().to_owned(),
                                ProtocolId::NetPerfRpcCompressed,
                                BlockOfBytes64K,
                                Duration::from_secs(5),
                            ));
                        }
                    }
                    None => break,
                }
            }
            res = rpc_handlers.select_next_some() => {}
        }
    }
}

async fn netperf_broadcast(state: NetPerfState) {
    loop {
        let _ = state.tx.send(NetPerfCommands::Broadcast).await;
    }
}

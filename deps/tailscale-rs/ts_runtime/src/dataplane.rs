use std::{
    fmt::{Debug, Formatter},
    sync::Arc,
};

use futures_util::StreamExt;
use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, Message, StreamMessage},
};
use ts_dataplane::async_tokio::{
    ActivePeers, DiscoBatch, FromOverlay, FromUnderlay, Rx, StunBatch, ToOverlay, ToUnderlay, Tx,
};
use ts_disco_protocol::{Packet, Plaintext};
use ts_hexdump::{AsHexExt, Case};
use ts_packet::PacketMut;
use ts_transport::{DynEndpoint, OverlayTransportId, UnderlayTransportId};

use crate::{
    Error, Task,
    env::Env,
    packetfilter::PacketFilterState,
    peer_tracker::PeerState,
    route_updater::{PeerRouteUpdate, SelfRouteUpdate},
    src_filter::SourceFilterState,
};

pub struct DataplaneActor {
    dataplane: Arc<ts_dataplane::async_tokio::DataPlane>,
    env: Env,
}

#[kameo::messages]
impl DataplaneActor {
    #[message]
    pub async fn new_overlay_transport(
        &self,
    ) -> (OverlayTransportId, Tx<FromOverlay>, Rx<ToOverlay>) {
        self.dataplane.new_overlay_transport().await
    }

    #[message]
    pub async fn new_underlay_transport(
        &self,
    ) -> (UnderlayTransportId, Rx<ToUnderlay>, Tx<FromUnderlay>) {
        self.dataplane.new_underlay_transport().await
    }

    /// Send a message directly to an underlay transport, bypassing the routing layer.
    #[message]
    pub async fn send_underlay(
        &self,
        underlay_id: UnderlayTransportId,
        endpoint: DynEndpoint,
        bufs: Vec<PacketMut>,
    ) -> bool {
        self.dataplane
            .send_underlay(underlay_id, endpoint, bufs)
            .await
    }
}

pub type DiscoPacket = yoke::Yoke<&'static Packet<Plaintext>, ts_packet::Packet>;

#[derive(Clone)]
pub struct IncomingDiscoMsg {
    pub transport: UnderlayTransportId,
    pub sender: DynEndpoint,
    pub packet: DiscoPacket,
}

impl Debug for IncomingDiscoMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.packet.get().fmt(f)
    }
}

impl AsRef<Packet<Plaintext>> for IncomingDiscoMsg {
    fn as_ref(&self) -> &Packet<Plaintext> {
        self.packet.get()
    }
}

struct DiscoInternal(DiscoBatch);

#[derive(Debug, Clone)]
#[expect(dead_code)]
pub struct IncomingStunMsg {
    pub transport: UnderlayTransportId,
    pub sender: DynEndpoint,
    pub pkt: ts_packet::Packet,
}

struct StunInternal(StunBatch);

impl kameo::Actor for DataplaneActor {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let (dataplane, disco, stun, active_peers) =
            ts_dataplane::async_tokio::DataPlane::new(env.keys.node_keys.clone());

        let dataplane = Arc::new(dataplane);

        slf.attach_stream(
            tokio_stream::wrappers::UnboundedReceiverStream::new(disco).map(DiscoInternal),
            (),
            (),
        );

        slf.attach_stream(
            tokio_stream::wrappers::UnboundedReceiverStream::new(stun).map(StunInternal),
            (),
            (),
        );

        slf.attach_stream(
            tokio_stream::wrappers::WatchStream::new(active_peers),
            (),
            (),
        );

        env.subscribe::<PeerRouteUpdate>(&slf).await?;
        env.subscribe::<SelfRouteUpdate>(&slf).await?;
        env.subscribe::<PacketFilterState>(&slf).await?;
        env.subscribe::<SourceFilterState>(&slf).await?;
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        let task_dataplane = dataplane.clone();

        Task::spawn_link(&slf, async move {
            task_dataplane.run().await;
        })
        .await;

        tracing::trace!("dataplane running");
        env.register(None, &slf).await?;

        Ok(Self { dataplane, env })
    }
}

impl Message<StreamMessage<DiscoInternal, (), ()>> for DataplaneActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<DiscoInternal, (), ()>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let (transport_id, ep, bufs) = match msg {
            StreamMessage::Next(pkt) => pkt.0,
            _ => return,
        };

        for mut buf in bufs {
            let pkt = tracing::debug_span!(
                "disco_ingest",
                ?transport_id,
                ?ep,
                sender_disco = tracing::field::Empty
            )
            .in_scope::<_, Option<IncomingDiscoMsg>>(|| {
                let pkt = match Packet::from_encrypted_bytes_mut(buf.as_mut()) {
                    Ok(pkt) => pkt,
                    Err(e) => {
                        tracing::error!(error = %e, "parsing disco message:\n{}",
                            buf.iter().hexdump_string(Case::Lower)
                        );
                        return None;
                    }
                };

                tracing::Span::current()
                    .record("sender_disco", tracing::field::display(pkt.sender_pubkey()));

                if let Err(e) = pkt.decrypt_in_place(&self.env.keys.disco_keys.private) {
                    tracing::error!(error = %e, "decrypting disco message");
                    return None;
                };

                let pkt = yoke::Yoke::<&'static Packet<Plaintext>, _>::try_attach_to_cart(
                    buf.freeze(),
                    // SAFETY: we just parsed this from the same buffer, so type/version are set correctly.
                    |buf| unsafe { Packet::from_bytes_unchecked(buf) },
                )
                .unwrap();

                let pkt = IncomingDiscoMsg {
                    transport: transport_id,
                    sender: ep.clone(),
                    packet: pkt,
                };

                tracing::trace!(?pkt, "decrypted disco message");

                Some(pkt)
            });

            if let Some(pkt) = pkt {
                self.env.publish_noretain(pkt).await.unwrap();
            }
        }
    }
}

impl Message<StreamMessage<StunInternal, (), ()>> for DataplaneActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<StunInternal, (), ()>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let (transport_id, ep, pkts) = match msg {
            StreamMessage::Next(pkt) => pkt.0,
            _ => return,
        };

        for pkt in pkts {
            self.env
                .publish_noretain(IncomingStunMsg {
                    transport: transport_id,
                    pkt: pkt.freeze(),
                    sender: ep.clone(),
                })
                .await
                .unwrap();
        }
    }
}

impl Message<StreamMessage<ActivePeers, (), ()>> for DataplaneActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<ActivePeers, (), ()>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        let peers = match msg {
            StreamMessage::Next(pkt) => pkt,
            StreamMessage::Finished(_) => {
                // TODO(npry): apply to all stream msg handlers
                tracing::warn!("active peers stream died, killing dataplane");
                ctx.stop();
                return;
            }
            StreamMessage::Started(_) => {
                return;
            }
        };

        tracing::debug!(active_peers = ?peers, "new active_peers");

        self.env.publish(peers).await.unwrap();
    }
}

impl Message<PeerRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PeerRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        tracing::trace!("applying peer route update");

        let dp = &mut *self.dataplane.inner().await;
        dp.or_out.swap(msg.inner.overlay_out_routes.clone());

        dp.ur_out.table = msg.inner.underlay_routes.clone();
    }
}

impl Message<SelfRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SelfRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.or_in.swap(msg.overlay_in_routes.as_ref().clone());
        }

        tracing::trace!("applied self route update");
    }
}

impl Message<PacketFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PacketFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.packet_filter = msg.0;
        }

        tracing::trace!("applied new packet filter");
    }
}

impl Message<SourceFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SourceFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.src_filter_in = msg.0;
        }

        tracing::trace!("applied new source filter");
    }
}

impl Message<Arc<PeerState>> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let mut dp = self.dataplane.inner().await;
            let wg = &mut dp.wireguard;

            for &upsert in &msg.upserts {
                let (_, node) = msg.peers.get(&upsert).unwrap();

                wg.upsert_peer(ts_tunnel::PeerConfig::new(
                    ts_tunnel::PeerId(upsert.0),
                    node.node_key,
                    [0u8; 32],
                ));
            }

            for delete in &msg.deletions {
                wg.remove_peer(ts_tunnel::PeerId(delete.0));
            }
        }

        tracing::trace!("applied new peer state");
    }
}

// ThinkTerm (TCP replies): exercise filtering after real WireGuard authentication.
#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc, time::Instant};

    use ts_bart::{RoutingTable, Table};
    use ts_dataplane::DataPlane;
    use ts_keys::NodeKeyPair;
    use ts_overlay_router::inbound::RouteAction;
    use ts_packet::PacketMut;
    use ts_packetfilter::{BTreeFilter, DropAllFilter, DstMatch, IpProto, Rule, SrcMatch};
    use ts_tunnel::{Endpoint, PeerConfig, PeerId};

    fn packet(src: &str, dst: &str, protocol: u8, flags: u8) -> PacketMut {
        let transport_len = if protocol == 6 { 20 } else { 8 };
        let mut bytes = match (src.parse().unwrap(), dst.parse().unwrap()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let mut bytes = PacketMut::new(20 + transport_len);
                bytes[0] = 0x45;
                bytes[2..4].copy_from_slice(&((20 + transport_len) as u16).to_be_bytes());
                bytes[8] = 64;
                bytes[9] = protocol;
                bytes[12..16].copy_from_slice(&src.octets());
                bytes[16..20].copy_from_slice(&dst.octets());
                bytes
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let mut bytes = PacketMut::new(40 + transport_len);
                bytes[0] = 0x60;
                bytes[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
                bytes[6] = protocol;
                bytes[7] = 64;
                bytes[8..24].copy_from_slice(&src.octets());
                bytes[24..40].copy_from_slice(&dst.octets());
                bytes
            }
            _ => panic!("address families must match"),
        };
        let offset = bytes.len() - transport_len;
        bytes[offset..offset + 2].copy_from_slice(&1234u16.to_be_bytes());
        bytes[offset + 2..offset + 4].copy_from_slice(&49152u16.to_be_bytes());
        if protocol == 6 {
            bytes[offset + 12] = 0x50;
            bytes[offset + 13] = flags;
        } else {
            bytes[offset + 4..offset + 6].copy_from_slice(&8u16.to_be_bytes());
        }
        bytes
    }

    fn endpoints(src: &str, dst: &str) -> (Endpoint, DataPlane) {
        let sender_key = NodeKeyPair::random();
        let receiver_key = NodeKeyPair::random();
        let mut sender = Endpoint::new(sender_key.clone());
        let mut receiver = DataPlane::new(receiver_key.clone());
        sender.upsert_peer(PeerConfig::new(PeerId(1), receiver_key.public, [0; 32]));
        receiver
            .wireguard
            .upsert_peer(PeerConfig::new(PeerId(1), sender_key.public, [0; 32]));
        let now = Instant::now();
        let initiation = sender.send(now, [(PeerId(1), vec![PacketMut::new(0)])]);
        let response = receiver
            .wireguard
            .recv(now, initiation.to_peers.into_values().flatten());
        let confirmation = sender.recv(now, response.to_peers.into_values().flatten());
        receiver
            .wireguard
            .recv(now, confirmation.to_peers.into_values().flatten());

        let prefix = if src.contains(':') { 128 } else { 32 };
        let mut source_routes = Table::default();
        source_routes.insert(
            format!("{src}/{prefix}").parse().unwrap(),
            ts_transport::PeerId(1),
        );
        receiver.src_filter_in = Arc::new(source_routes);
        let mut destination_routes = Table::default();
        destination_routes.insert(
            format!("{dst}/{prefix}").parse().unwrap(),
            RouteAction::ToOverlay(1.into()),
        );
        receiver.or_in.swap(destination_routes);
        (sender, receiver)
    }

    fn delivered(sender: &mut Endpoint, receiver: &mut DataPlane, mut packet: PacketMut) -> bool {
        let expected = packet.clone();
        packet.grow_back((16 - packet.len() % 16) % 16);
        let sent = sender.send(Instant::now(), [(PeerId(1), vec![packet])]);
        assert!(!sent.to_peers.is_empty(), "encrypted packet was not sent");
        let received = receiver.process_inbound(sent.to_peers.into_values().flatten());
        let packets: Vec<_> = received.to_local.into_values().flatten().collect();
        if packets.is_empty() {
            false
        } else {
            assert_eq!(packets, vec![expected]);
            true
        }
    }

    #[test]
    fn non_initiating_tcp_reaches_netstack_without_prior_flow_or_grants() {
        for (src, dst) in [
            ("100.64.0.1", "100.64.0.3"),
            ("fd7a:115c:a1e0::1", "fd7a:115c:a1e0::3"),
        ] {
            let (mut sender, mut receiver) = endpoints(src, dst);
            let prefix = if src.contains(':') { 128 } else { 32 };
            receiver.packet_filter = Arc::new(BTreeFilter::from([(
                "control".into(),
                vec![Rule {
                    src: SrcMatch {
                        pfxs: vec![format!("{src}/{prefix}").parse().unwrap()],
                        caps: vec![],
                    },
                    protos: vec![IpProto::TCP],
                    dst: vec![DstMatch {
                        ips: vec![format!("{dst}/{prefix}").parse().unwrap()],
                        ports: 49152..=49152,
                    }],
                }],
            )]));
            assert!(
                delivered(&mut sender, &mut receiver, packet(src, dst, 6, 0x02)),
                "permitted SYN control failed"
            );
            // A fresh session rules out state retained from the permitted SYN.
            let (mut sender, mut receiver) = endpoints(src, dst);
            receiver.packet_filter = Arc::new(DropAllFilter);
            for flags in [0x12, 0x10, 0x18, 0x11, 0x14, 0x01, 0x04, 0x00] {
                let mut response = packet(src, dst, 6, flags);
                if flags == 0x18 {
                    response.extend_from_slice(b"data");
                    if src.contains(':') {
                        response[4..6].copy_from_slice(&24u16.to_be_bytes());
                    } else {
                        response[2..4].copy_from_slice(&44u16.to_be_bytes());
                    }
                }
                assert!(
                    delivered(&mut sender, &mut receiver, response),
                    "non-initiating TCP {flags:#x} to {dst} was dropped without a grant"
                );
            }
        }
    }

    #[test]
    fn unsolicited_syn_udp_and_spoofed_sources_remain_denied() {
        for (src, dst, spoofed, other_dst) in [
            ("100.64.0.1", "100.64.0.3", "100.64.0.2", "100.64.0.4"),
            (
                "fd7a:115c:a1e0::1",
                "fd7a:115c:a1e0::3",
                "fd7a:115c:a1e0::2",
                "fd7a:115c:a1e0::4",
            ),
        ] {
            let (mut sender, mut receiver) = endpoints(src, dst);
            for flags in [0x02, 0x03, 0x06, 0xc2] {
                assert!(
                    !delivered(&mut sender, &mut receiver, packet(src, dst, 6, flags)),
                    "unsolicited SYN admitted"
                );
            }
            assert!(
                !delivered(&mut sender, &mut receiver, packet(src, dst, 17, 0)),
                "UDP admitted without a grant"
            );
            assert!(
                !delivered(&mut sender, &mut receiver, packet(spoofed, dst, 6, 0x12)),
                "unknown source admitted"
            );
            let prefix = if src.contains(':') { 128 } else { 32 };
            receiver.wireguard.upsert_peer(PeerConfig::new(
                PeerId(2),
                NodeKeyPair::random().public,
                [0; 32],
            ));
            let mut source_routes = Table::default();
            source_routes.insert(
                format!("{src}/{prefix}").parse().unwrap(),
                ts_transport::PeerId(1),
            );
            source_routes.insert(
                format!("{spoofed}/{prefix}").parse().unwrap(),
                ts_transport::PeerId(2),
            );
            receiver.src_filter_in = Arc::new(source_routes);
            assert!(
                !delivered(&mut sender, &mut receiver, packet(spoofed, dst, 6, 0x12)),
                "another configured peer's source admitted"
            );
            assert!(
                delivered(&mut sender, &mut receiver, packet(src, dst, 6, 0x12)),
                "authenticated source-matched TCP control failed"
            );
            assert!(
                !delivered(&mut sender, &mut receiver, packet(src, other_dst, 6, 0x12)),
                "unrouted destination admitted"
            );
            let mut destination_routes = Table::default();
            destination_routes.insert(
                format!("{dst}/{prefix}").parse().unwrap(),
                RouteAction::Drop,
            );
            receiver.or_in.swap(destination_routes);
            assert!(
                !delivered(&mut sender, &mut receiver, packet(src, dst, 6, 0x12)),
                "explicit Drop destination admitted"
            );
        }
    }

    #[test]
    fn malformed_and_fragmented_tcp_do_not_gain_the_flag_exception() {
        for (src, dst) in [
            ("100.64.0.1", "100.64.0.3"),
            ("fd7a:115c:a1e0::1", "fd7a:115c:a1e0::3"),
        ] {
            let (mut sender, mut receiver) = endpoints(src, dst);
            let valid = packet(src, dst, 6, 0x10);
            assert!(
                delivered(&mut sender, &mut receiver, valid.clone()),
                "valid ACK control failed"
            );
            let ipv6 = src.contains(':');
            let offset = if ipv6 { 40 } else { 20 };
            let mut truncated = valid.clone();
            truncated.resize(offset + 14);
            let mut short_header = valid.clone();
            short_header[offset + 12] = 0x40;
            let mut long_header = valid.clone();
            long_header[offset + 12] = 0xf0;
            let mut first_fragment = valid.clone();
            first_fragment.extend_from_slice(&[0; 4]);
            if ipv6 {
                first_fragment.grow_back(8);
                first_fragment.copy_within(40..64, 48);
                first_fragment[6] = 44;
                first_fragment[40..48].copy_from_slice(&[6, 0, 0, 1, 0, 0, 0, 1]);
            } else {
                first_fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
            }
            let mut later_fragment = first_fragment.clone();
            if ipv6 {
                later_fragment[42..44].copy_from_slice(&24u16.to_be_bytes());
            } else {
                later_fragment[6..8].copy_from_slice(&3u16.to_be_bytes());
            }
            for (name, mut malformed) in [
                ("truncated TCP", truncated),
                ("data offset below minimum", short_header),
                ("data offset beyond payload", long_header),
                ("first fragment with ACK-like bytes", first_fragment),
                ("later fragment with ACK-like bytes", later_fragment),
            ] {
                // IP lengths must exclude WireGuard padding even for truncated TCP.
                let len = malformed.len();
                if ipv6 {
                    malformed[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
                } else {
                    malformed[2..4].copy_from_slice(&(len as u16).to_be_bytes());
                }
                assert!(
                    !delivered(&mut sender, &mut receiver, malformed),
                    "{name} to {dst} admitted without a grant"
                );
            }
        }
    }
}

use core::net::{Ipv4Addr, Ipv6Addr};
use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, StreamMessage},
    prelude::{Message, ReplySender},
    reply::DelegatedReply,
    supervision::RestartPolicy,
};
use ts_control::{
    ControlDialer, DialPlan, Endpoint, Error as ControlError, Node, RegistrationError, StateUpdate,
    TailnetAddress,
    client::{HttpConn, handle_ping, map_stream, send_map_request},
};

use crate::{
    Task,
    derp_latency::{DerpLatencyMeasurement, DerpLatencyMeasurer},
    direct,
    env::Env,
    retained_bus::GetRetained,
};

/// Actor responsible for maintaining the connection to control.
///
/// This actor is responsible for proxying the map response stream onto the message bus.
pub struct ControlRunner {
    params: Params,
    state: RegState,

    derp_latency_measurement: Option<DerpLatencyMeasurement>,

    endpoints: Vec<Endpoint>,

    self_node: Option<Node>,
    // ThinkTerm (control reconnect): configured addresses outlive the current map stream, not the runtime.
    local_addresses: Option<TailnetAddress>,
    pending_node_requests: Vec<PendingNodeRequest>,
}

enum RegState {
    NotRegistered {
        pending_auth_requests: Vec<ReplySender<Option<url::Url>>>,
    },
    AuthRequired(url::Url),
    Registered(HttpConn),
    // ThinkTerm (sign-in state): added.
    /// Control turned the device away, for the reason given. The runner does not try again;
    /// it stays to say why (see `current_registration_error`) rather than stopping, which would
    /// leave every question to it unanswered and the reason only in the log.
    Failed(String),
}

/// Control runner args.
#[derive(Clone)]
pub struct Params {
    /// Control config.
    pub(crate) config: ts_control::Config,

    /// Auth key (if needed).
    pub(crate) auth_key: Option<String>,

    /// The [`Env`] for this actor.
    pub(crate) env: Env,
}

#[doc(hidden)]
#[derive(Debug, Clone, thiserror::Error)]
pub enum ControlRunnerError {
    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Crate(#[from] crate::Error),
}

#[derive(Clone)]
struct AuthRequired(url::Url);

struct RegisterResult(Result<HttpConn, RegistrationError>);

impl kameo::Actor for ControlRunner {
    type Args = Params;
    type Error = ControlRunnerError;

    async fn on_start(params: Params, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        Task::supervise_with(&slf, {
            let aref = slf.downgrade();
            let params = params.clone();

            move || {
                let aref = aref.clone();
                let params = params.clone();

                async move {
                    // ThinkTerm (control reconnect): retry outside on_start so shutdown can cancel an outage.
                    let mut pause = Duration::from_secs(1);
                    let client = loop {
                        match params
                            .env
                            .ask::<DialerActor, _>(
                                None,
                                DialNext {
                                    url: params.config.server_url.clone(),
                                },
                                true,
                            )
                            .await
                        {
                            Ok(client) => break client,
                            Err(err) => {
                                tracing::warn!(error = %err, ?pause, "control dial failed; retrying");
                                tokio::time::sleep(pause).await;
                                pause = (pause * 2).min(Duration::from_secs(30));
                            }
                        }
                    };
                    let mut followup = None;

                    loop {
                        let result = ts_control::register(
                            &params.config,
                            &params.config.server_url,
                            params.auth_key.as_deref(),
                            followup,
                            &params.env.keys,
                            &client,
                        )
                        .await;

                        if let Err(RegistrationError::MachineNotAuthorized(Some(u))) = result {
                            tracing::warn!(auth_url = %u, "machine not authorized");
                            followup = Some(u.clone());

                            let Some(aref) = aref.upgrade() else {
                                // if the control runner is dead, we should die shortly, no reason
                                // to keep running.
                                return;
                            };

                            if let Err(e) = aref.tell(AuthRequired(u)).await {
                                tracing::error!(error = %e, "failed to tell control runner required auth");
                            }

                            continue;
                        }

                        let Some(aref) = aref.upgrade() else {
                            return;
                        };
                        drop(aref.tell(RegisterResult(result.map(|_| client))).await);

                        break;
                    }
                }
            }
        })
        .restart_policy(RestartPolicy::Transient)
        .spawn()
        .await;

        params.env.subscribe::<DerpLatencyMeasurement>(&slf).await?;
        params.env.subscribe::<direct::NewEndpoints>(&slf).await?;

        // ThinkTerm (control reconnect): restarted actor ids do not receive retained subscriptions again.
        let endpoints = params
            .env
            .bus
            .ask(GetRetained::<direct::NewEndpoints>::new())
            .await
            .map_err(crate::Error::from)?
            .map_or_else(Vec::new, |endpoints| endpoints.0.to_vec());
        let derp_latency_measurement = params
            .env
            .bus
            .ask(GetRetained::<DerpLatencyMeasurement>::new())
            .await
            .map_err(crate::Error::from)?;
        let local_addresses = params
            .env
            .bus
            .ask(GetRetained::<TailnetAddress>::new())
            .await
            .map_err(crate::Error::from)?;

        DerpLatencyMeasurer::supervise(&slf, params.env.clone())
            .spawn()
            .await;

        params.env.register(None, &slf).await?;

        Ok(Self {
            state: RegState::NotRegistered {
                pending_auth_requests: Default::default(),
            },
            params,
            derp_latency_measurement,
            endpoints,
            self_node: None,
            local_addresses,
            pending_node_requests: Default::default(),
        })
    }
}

#[kameo::messages]
impl ControlRunner {
    /// Fetch the IPv4 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv4(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv4Addr>>>,
    ) -> DelegatedReply<Option<Ipv4Addr>> {
        if let Some(addresses) = &self.local_addresses {
            return ctx.reply(Some(addresses.ipv4.addr()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending_node_requests
                .push(PendingNodeRequest::Ipv4(replier));
        }

        deleg
    }

    /// Fetch the IPv6 address for this tailscale device.
    #[message(ctx)]
    pub fn ipv6(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Ipv6Addr>>>,
    ) -> DelegatedReply<Option<Ipv6Addr>> {
        if let Some(addresses) = &self.local_addresses {
            return ctx.reply(Some(addresses.ipv6.addr()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending_node_requests
                .push(PendingNodeRequest::Ipv6(replier));
        }

        deleg
    }

    /// Fetch the self node for this tailscale device.
    #[message(ctx)]
    pub fn self_node(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
    ) -> DelegatedReply<Option<Node>> {
        if let Some(node) = &self.self_node {
            return ctx.reply(Some(node.clone()));
        }

        let (deleg, replier) = ctx.reply_sender();
        if let Some(replier) = replier {
            self.pending_node_requests
                .push(PendingNodeRequest::SelfNode(replier));
        }

        deleg
    }

    // ThinkTerm (sign-in state): the next three messages are ours.
    /// The node from the latest netmap, without waiting for one to arrive.
    #[message]
    pub fn current_self_node(&mut self) -> Option<Node> {
        self.self_node.clone()
    }

    /// The current registration state: None while connecting, Some(None)
    /// once registered, or Some(Some(url)) while approval is needed.
    /// Unlike auth_url, this does not retain a pending request.
    #[message]
    pub fn current_auth_url(&mut self) -> Option<Option<url::Url>> {
        match &self.state {
            RegState::Registered(..) => Some(None),
            RegState::AuthRequired(url) => Some(Some(url.clone())),
            RegState::NotRegistered { .. } | RegState::Failed(..) => None,
        }
    }

    /// Why control turned this device away, once it has.
    #[message]
    pub fn current_registration_error(&mut self) -> Option<String> {
        match &self.state {
            RegState::Failed(reason) => Some(reason.clone()),
            _ => None,
        }
    }

    /// Wait for a report of whether interactive auth is needed, and if so, what the URL is.
    #[message(ctx)]
    pub fn auth_url(
        &mut self,
        ctx: &mut Context<Self, DelegatedReply<Option<url::Url>>>,
    ) -> DelegatedReply<Option<url::Url>> {
        match &mut self.state {
            RegState::Registered(..) => ctx.reply(None),
            RegState::AuthRequired(u) => ctx.reply(Some(u.clone())),
            RegState::NotRegistered {
                pending_auth_requests,
            } => {
                let (deleg, replier) = ctx.reply_sender();
                if let Some(replier) = replier {
                    pending_auth_requests.push(replier);
                }

                deleg
            }
            // ThinkTerm (sign-in state): added.
            // Turned away: no answer will come, and the request goes with its reply.
            RegState::Failed(..) => ctx.reply_sender().0,
        }
    }
}

impl ControlRunner {
    /// Call `f` with a map request built from the current control actor state.
    ///
    /// `stream` dictates whether the request is built for a streaming netmap response or as a
    /// request to update to this node's fields in control.
    ///
    /// This takes a closure rather than returning the built request for lifetime reasons.
    async fn with_map_request<T>(
        &self,
        stream: bool,
        f: impl AsyncFnOnce(ts_control::MapRequest) -> T,
    ) -> T {
        let mut mrb = ts_control::MapRequestBuilder::new(&self.params.env.keys);

        mrb = if stream {
            mrb.as_stream()
        } else {
            mrb.as_request()
        };

        mrb = mrb.endpoints(self.endpoints.clone());

        if let Some(hostname) = self.params.config.hostname.as_deref() {
            mrb = mrb.hostname(hostname);
        }

        if let Some(latency) = &self.derp_latency_measurement {
            if let Some(result) = latency.measurement.first() {
                mrb = mrb.preferred_derp(result.id);
            };

            let iter = latency.measurement.iter().map(|result| {
                (
                    result.latency_map_key.as_str(),
                    result.latency.as_secs_f64(),
                )
            });

            mrb = mrb.derp_latencies(iter);
        }

        let client_name = self.params.config.format_client_name();

        let mut request = mrb.build();
        let host_info = request.host_info.get_or_insert_default();
        host_info.app = &client_name;
        host_info.ipn_version = ts_control::PKG_VERSION;

        f(request).await
    }

    async fn update_map_request(&self) {
        let RegState::Registered(conn) = &self.state else {
            tracing::debug!("attempt to update map request while not registered");
            return;
        };

        self.with_map_request(false, async |req| {
            send_map_request(
                req,
                &self.params.config.server_url.join("machine/map").unwrap(),
                conn,
            )
            .await
        })
        .await
        .unwrap();
    }
}

impl Message<AuthRequired> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        AuthRequired(auth_url): AuthRequired,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let RegState::NotRegistered {
            pending_auth_requests,
        } = core::mem::replace(&mut self.state, RegState::AuthRequired(auth_url.clone()))
        else {
            tracing::warn!("got duplicate authrequired message");
            return;
        };

        for req in pending_auth_requests.into_iter() {
            req.send(Some(auth_url.clone()));
        }
    }
}

impl Message<RegisterResult> for ControlRunner {
    type Reply = ();

    #[tracing::instrument(skip_all, fields(result = ?msg.0))]
    async fn handle(&mut self, msg: RegisterResult, ctx: &mut Context<Self, Self::Reply>) {
        if matches!(self.state, RegState::Registered(..)) {
            tracing::warn!("got register result after already in registered state");
            return;
        }

        let conn = match msg.0 {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(error = %e, "unable to register with control server");
                // ThinkTerm (sign-in state): was `ctx.stop()`.
                // Pending auth requests go unanswered with it.
                self.state = RegState::Failed(registration_failure(&e));
                return;
            }
        };

        let old_state = core::mem::replace(&mut self.state, RegState::Registered(conn.clone()));

        if let RegState::NotRegistered {
            pending_auth_requests,
        } = old_state
        {
            for req in pending_auth_requests {
                req.send(None);
            }
        }

        let reader = self
            .with_map_request(true, async |req| {
                let map_url = self.params.config.server_url.join("machine/map").unwrap();

                send_map_request(req, &map_url, &conn).await
            })
            .await
            .unwrap();

        let stream = map_stream(reader).map(Arc::new);

        ctx.actor_ref().attach_stream(stream.boxed(), (), ());
    }
}

// ThinkTerm (sign-in state): added.
/// What a failed registration says to whoever looks at the device.
fn registration_failure(err: &RegistrationError) -> String {
    match err {
        RegistrationError::MachineNotAuthorized(None) => {
            "the control server turned this machine away: the auth key may be wrong, used up or \
             expired"
                .to_string()
        }
        RegistrationError::NetworkError => {
            "the control server could not be reached while signing in".to_string()
        }
        other => format!("signing in failed: {other}"),
    }
}

enum PendingNodeRequest {
    Ipv4(ReplySender<Option<Ipv4Addr>>),
    Ipv6(ReplySender<Option<Ipv6Addr>>),
    SelfNode(ReplySender<Option<Node>>),
}

impl Message<StreamMessage<Arc<StateUpdate>, (), ()>> for ControlRunner {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<Arc<StateUpdate>, (), ()>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        let msg = match msg {
            StreamMessage::Started(_) => {
                tracing::trace!("started listening to state updates");
                return;
            }

            StreamMessage::Next(msg) => msg,

            StreamMessage::Finished(_) => {
                tracing::error!("state update stream terminated");
                ctx.stop();
                return;
            }
        };

        if let RegState::Registered(conn) = &self.state {
            let _ = handle_ping(&msg, &self.params.config.server_url, conn).await;
        }

        if let Some(dial_plan) = &msg.dial_plan
            && self
                .params
                .env
                .ask::<DialerActor, _>(
                    None,
                    UpdateDialPlan {
                        dial_plan: dial_plan.clone(),
                    },
                    true,
                )
                .await
                .unwrap()
        {
            tracing::trace!(new_dial_plan = ?dial_plan);
        }

        if let Some(node) = msg.node.as_ref() {
            // ThinkTerm (control reconnect): node-less deltas must not erase configured addresses.
            self.local_addresses = Some(node.tailnet_address.clone());
            if let Err(e) = self.params.env.publish(node.tailnet_address.clone()).await {
                tracing::error!(error = %e, "retaining local addresses");
            }
            self.self_node = Some(node.clone());
        }

        if let Err(e) = self.params.env.publish(msg).await {
            tracing::error!(error = %e, "publishing netmap update");
        }

        if let Some(node) = &self.self_node {
            for req in self.pending_node_requests.drain(..) {
                match req {
                    PendingNodeRequest::Ipv4(sender) => {
                        sender.send(Some(node.tailnet_address.ipv4.addr()));
                    }
                    PendingNodeRequest::Ipv6(sender) => {
                        sender.send(Some(node.tailnet_address.ipv6.addr()));
                    }
                    PendingNodeRequest::SelfNode(sender) => {
                        sender.send(Some(node.clone()));
                    }
                }
            }
        }
    }
}

impl Message<direct::NewEndpoints> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: direct::NewEndpoints, _ctx: &mut Context<Self, Self::Reply>) {
        if self.endpoints == msg.0.as_ref() {
            return;
        }

        self.endpoints = msg.0.to_vec();
        self.update_map_request().await;
    }
}

impl Message<DerpLatencyMeasurement> for ControlRunner {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, _ctx: &mut Context<Self, Self::Reply>) {
        if self.derp_latency_measurement.as_ref() == Some(&msg) {
            return;
        }

        self.derp_latency_measurement = Some(msg);
        self.update_map_request().await;
    }
}

/// Control server dialer.
pub struct DialerActor {
    dialer: ControlDialer,
    env: Env,
}

impl kameo::Actor for DialerActor {
    type Args = Env;
    type Error = crate::Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.register(None, &slf).await?;

        Ok(Self {
            dialer: Default::default(),
            env,
        })
    }
}

#[kameo::messages]
impl DialerActor {
    #[message]
    async fn dial_next(&mut self, url: url::Url) -> Result<HttpConn, ts_control::Error> {
        self.dialer
            .full_connect_next(&url, &self.env.keys.machine_keys)
            .await
    }

    #[message]
    fn update_dial_plan(&mut self, dial_plan: DialPlan) -> bool {
        self.dialer.update_dial_plan(&dial_plan)
    }
}

// ThinkTerm (sign-in state): the tests are ours.
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ts_control::RegistrationError;

    use super::*;

    struct OutageSupervisor;

    impl kameo::Actor for OutageSupervisor {
        type Args = Params;
        type Error = crate::Error;

        async fn on_start(params: Params, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
            params.env.bus.link(&slf).await;
            params.env.scheduler.link(&slf).await;
            params.env.registry.link(&slf).await;
            DialerActor::supervise(&slf, params.env.clone())
                .spawn()
                .await;
            ControlRunner::supervise(&slf, params).spawn().await;
            Ok(Self)
        }
    }

    #[tokio::test]
    async fn an_unreachable_control_server_does_not_kill_the_runtime() {
        let supervisor = OutageSupervisor::spawn(Params {
            config: ts_control::Config {
                server_url: "http://127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            },
            auth_key: None,
            env: Env::new(ts_keys::NodeState::generate()),
        });
        supervisor.wait_for_startup_result().await.unwrap();
        let died = tokio::time::timeout(Duration::from_secs(2), supervisor.wait_for_shutdown())
            .await
            .is_ok();
        supervisor.kill();
        tokio::time::timeout(Duration::from_secs(2), supervisor.wait_for_shutdown())
            .await
            .expect("runtime shutdown stalled while control is unreachable");
        assert!(!died, "control dial failures killed the runtime supervisor");
    }

    #[test]
    fn a_sign_in_turned_away_says_why() {
        let refused = registration_failure(&RegistrationError::MachineNotAuthorized(None));
        assert!(refused.contains("auth key"), "{refused}");
        let unreachable = registration_failure(&RegistrationError::NetworkError);
        assert!(
            unreachable.contains("could not be reached"),
            "{unreachable}"
        );
    }

    fn node_update(node: Option<Node>) -> Arc<StateUpdate> {
        Arc::new(StateUpdate {
            derp: None,
            node,
            peer_update: None,
            ping: None,
            packetfilter: None,
            pop_browser_url: None,
            dial_plan: None,
        })
    }

    #[tokio::test]
    async fn configured_addresses_survive_a_control_restart_without_claiming_fresh_state() {
        let env = Env::new(ts_keys::NodeState::generate());
        let supervisor = OutageSupervisor::spawn(Params {
            config: ts_control::Config {
                server_url: "http://127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            },
            auth_key: None,
            env: env.clone(),
        });
        supervisor.wait_for_startup_result().await.unwrap();
        env.wait::<ControlRunner>(None).await.unwrap();
        let runner = env.lookup::<ControlRunner>(None).await.unwrap();
        assert_eq!(runner.ask(CurrentAuthUrl).await.unwrap(), None);
        assert_eq!(runner.ask(CurrentSelfNode).await.unwrap(), None);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), async { runner.ask(Ipv4).await })
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), async { runner.ask(Ipv6).await })
                .await
                .is_err()
        );

        let mut node = Node {
            id: 1,
            stable_id: ts_control::StableNodeId("self".into()),
            hostname: "self".into(),
            capability_version: Default::default(),
            status: ts_control::NodeStatus::Unknown,
            tailnet: None,
            node_capabilities: Default::default(),
            tags: vec![],
            tailnet_address: ts_control::TailnetAddress {
                ipv4: "100.64.0.1/32".parse().unwrap(),
                ipv6: "fd7a:115c:a1e0::1/128".parse().unwrap(),
            },
            node_key: env.keys.node_keys.public,
            node_key_expiry: None,
            machine_key: None,
            disco_key: None,
            tailnet_lock_key_signature: None,
            accepted_routes: vec![],
            underlay_addresses: vec![],
            derp_region: None,
            device: Default::default(),
        };
        runner
            .ask(StreamMessage::Next(node_update(Some(node.clone()))))
            .await
            .unwrap();
        assert_eq!(
            runner.ask(Ipv4).await.unwrap(),
            Some("100.64.0.1".parse().unwrap())
        );
        assert_eq!(
            runner.ask(Ipv6).await.unwrap(),
            Some("fd7a:115c:a1e0::1".parse().unwrap())
        );
        assert_eq!(
            runner.ask(CurrentSelfNode).await.unwrap(),
            Some(node.clone())
        );
        runner
            .ask(StreamMessage::Next(node_update(None)))
            .await
            .unwrap();
        assert!(
            env.bus
                .ask(GetRetained::<Arc<StateUpdate>>::new())
                .await
                .unwrap()
                .unwrap()
                .node
                .is_none()
        );

        runner
            .ask(StreamMessage::<Arc<StateUpdate>, (), ()>::Finished(()))
            .await
            .unwrap();
        let fresh_node = env
            .ask::<ControlRunner, _>(None, CurrentSelfNode, true)
            .await
            .unwrap();
        assert_eq!(
            fresh_node, None,
            "restart presented a stale node as a new map"
        );
        assert_eq!(
            env.ask::<ControlRunner, _>(None, CurrentAuthUrl, true)
                .await
                .unwrap(),
            None
        );
        let addresses = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(
                env.ask::<ControlRunner, _>(None, Ipv4, true),
                env.ask::<ControlRunner, _>(None, Ipv6, true),
            )
        })
        .await;
        let alive = supervisor.is_alive();

        node.tailnet_address.ipv4 = "100.64.0.2/32".parse().unwrap();
        node.tailnet_address.ipv6 = "fd7a:115c:a1e0::2/128".parse().unwrap();
        runner
            .ask(StreamMessage::Next(node_update(Some(node.clone()))))
            .await
            .unwrap();
        assert_eq!(
            runner.ask(Ipv4).await.unwrap(),
            Some("100.64.0.2".parse().unwrap())
        );
        assert_eq!(
            runner.ask(Ipv6).await.unwrap(),
            Some("fd7a:115c:a1e0::2".parse().unwrap())
        );
        runner
            .ask(StreamMessage::Next(node_update(None)))
            .await
            .unwrap();
        runner
            .ask(StreamMessage::<Arc<StateUpdate>, (), ()>::Finished(()))
            .await
            .unwrap();
        assert_eq!(
            env.ask::<ControlRunner, _>(None, CurrentSelfNode, true)
                .await
                .unwrap(),
            None
        );
        let replaced = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(
                env.ask::<ControlRunner, _>(None, Ipv4, true),
                env.ask::<ControlRunner, _>(None, Ipv6, true),
            )
        })
        .await
        .unwrap();
        assert_eq!(replaced.0.unwrap(), Some("100.64.0.2".parse().unwrap()));
        assert_eq!(
            replaced.1.unwrap(),
            Some("fd7a:115c:a1e0::2".parse().unwrap())
        );
        supervisor.kill();
        tokio::time::timeout(Duration::from_secs(2), supervisor.wait_for_shutdown())
            .await
            .unwrap();

        // A new runtime with the same persisted keys must configure its own netstack first.
        let cold_env = Env::new((*env.keys).clone());
        let cold = OutageSupervisor::spawn(Params {
            config: ts_control::Config {
                server_url: "http://127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            },
            auth_key: None,
            env: cold_env.clone(),
        });
        cold.wait_for_startup_result().await.unwrap();
        cold_env.wait::<ControlRunner>(None).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                cold_env.ask::<ControlRunner, _>(None, Ipv4, true)
            )
            .await
            .is_err()
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                cold_env.ask::<ControlRunner, _>(None, Ipv6, true)
            )
            .await
            .is_err()
        );
        assert_eq!(
            cold_env
                .ask::<ControlRunner, _>(None, CurrentSelfNode, true)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            cold_env
                .ask::<ControlRunner, _>(None, CurrentAuthUrl, true)
                .await
                .unwrap(),
            None
        );
        cold.kill();
        tokio::time::timeout(Duration::from_secs(2), cold.wait_for_shutdown())
            .await
            .unwrap();
        assert!(alive, "control restart killed the runtime");
        let (ipv4, ipv6) = addresses
            .expect("configured local addresses waited for unavailable control after restart");
        assert_eq!(ipv4.unwrap(), Some("100.64.0.1".parse().unwrap()));
        assert_eq!(ipv6.unwrap(), Some("fd7a:115c:a1e0::1".parse().unwrap()));
    }
}

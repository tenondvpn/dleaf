use std::convert::TryFrom;
use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use log::*;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;

use crate::{
    app::SyncDnsClient,
    common::{self, sniff},
    option,
    proxy::{OutboundDatagram, ProxyStream, TcpOutboundHandler, UdpOutboundHandler},
    session::{Network, Session, SocksAddr},
};

#[cfg(feature = "stat")]
use crate::app::SyncStatManager;

use super::outbound::manager::OutboundManager;
use super::router::Router;

#[inline]
fn log_request(
    sess: &Session,
    outbound_tag: &str,
    outbound_tag_color: colored::Color,
    handshake_time: Option<u128>,
) {
    let hs = handshake_time.map_or("failed".to_string(), |hs| format!("{}ms", hs));
    if !*crate::option::LOG_NO_COLOR {
        use colored::Colorize;
        let network_color = match sess.network {
            Network::Tcp => colored::Color::Blue,
            Network::Udp => colored::Color::Yellow,
        };
        debug!(
            "[{}] [{}] [{}] [{}] {}",
            &sess.inbound_tag,
            sess.network.to_string().color(network_color),
            outbound_tag.color(outbound_tag_color),
            hs,
            &sess.destination,
        );
    } else {
        debug!(
            "[{}] [{}] [{}] [{}] {}",
            sess.network, &sess.inbound_tag, outbound_tag, hs, &sess.destination,
        );
    }
}

pub struct Dispatcher {
    outbound_manager: Arc<RwLock<OutboundManager>>,
    router: Arc<RwLock<Router>>,
    dns_client: SyncDnsClient,
    #[cfg(feature = "stat")]
    stat_manager: SyncStatManager,
}

impl Dispatcher {
    pub fn new(
        outbound_manager: Arc<RwLock<OutboundManager>>,
        router: Arc<RwLock<Router>>,
        dns_client: SyncDnsClient,
        #[cfg(feature = "stat")] stat_manager: SyncStatManager,
    ) -> Self {
        Dispatcher {
            outbound_manager,
            router,
            dns_client,
            #[cfg(feature = "stat")]
            stat_manager,
        }
    }

    pub async fn dispatch_tcp<T>(&self, mut sess: Session, lhs: T)
    where
        T: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        let dispatch_start = tokio::time::Instant::now();
        info!(
            "[LEAF-PERF][DISPATCH][TCP] begin {} -> {}",
            sess.source,
            sess.destination
        );
        let mut lhs: Box<dyn ProxyStream> =
            if !sess.destination.is_domain() && sess.destination.port() == 443 {
                let sniff_start = tokio::time::Instant::now();
                let mut lhs = sniff::SniffingStream::new(lhs);
                match lhs.sniff().await {
                    Ok(res) => {
                        info!(
                            "[LEAF-PERF][DISPATCH][TCP] sniff done {} -> {} in {}ms",
                            sess.source,
                            sess.destination,
                            sniff_start.elapsed().as_millis()
                        );
                        if let Some(domain) = res {
                            debug!(
                                "sniffed domain {} for tcp link {} <-> {}",
                                &domain, &sess.source, &sess.destination,
                            );
                            sess.destination =
                                match SocksAddr::try_from((&domain, sess.destination.port())) {
                                    Ok(a) => a,
                                    Err(e) => {
                                        warn!(
                                            "convert sniffed domain {} to destination failed: {}",
                                            &domain, e,
                                        );
                                        return;
                                    }
                                };
                        }
                    }
                    Err(e) => {
                        info!(
                            "[LEAF-PERF][DISPATCH][TCP] sniff failed {} -> {} in {}ms: {}",
                            &sess.source,
                            &sess.destination,
                            sniff_start.elapsed().as_millis(),
                            e
                        );
                        return;
                    }
                }
                Box::new(lhs)
            } else {
                Box::new(lhs)
            };

        let outbound = {
            let route_start = tokio::time::Instant::now();
            let router = self.router.read().await;
            match router.pick_route(&sess).await {
                Ok(tag) => {
                    info!(
                        "[LEAF-PERF][DISPATCH][TCP] picked route [{}] for {} -> {} in {}ms",
                        tag, &sess.source, &sess.destination, route_start.elapsed().as_millis()
                    );
                    tag.to_owned()
                }
                Err(err) => {
                    info!(
                        "[LEAF-PERF][DISPATCH][TCP] pick route failed for {} -> {} in {}ms: {}",
                        &sess.source,
                        &sess.destination,
                        route_start.elapsed().as_millis(),
                        err
                    );
                    if let Some(tag) = self.outbound_manager.read().await.default_handler() {
                        info!(
                            "[LEAF-PERF][DISPATCH][TCP] picked default route [{}] for {} -> {}",
                            tag, &sess.source, &sess.destination
                        );
                        tag
                    } else {
                        warn!("[LEAF-PERF][DISPATCH][TCP] no handlers");
                        if let Err(e) = lhs.shutdown().await {
                            debug!(
                                "tcp downlink {} <- {} error: {}",
                                &sess.source, &sess.destination, e,
                            );
                        }
                        return;
                    }
                }
            }
        };

        sess.outbound_tag = outbound.clone();

        let h = if let Some(h) = self.outbound_manager.read().await.get(&outbound) {
            h
        } else {
            // FIXME use  the default handler
            warn!("[LEAF-PERF][DISPATCH][TCP] handler [{}] not found", outbound);
            if let Err(e) = lhs.shutdown().await {
                debug!(
                    "tcp downlink {} <- {} error: {}",
                    &sess.source, &sess.destination, e,
                );
            }
            return;
        };

        let handshake_start = tokio::time::Instant::now();
        info!(
            "[LEAF-PERF][DISPATCH][TCP] connect outbound begin {} -> {} via [{}]",
            sess.source,
            sess.destination,
            h.tag()
        );
        let stream =
            match crate::proxy::connect_tcp_outbound(&sess, self.dns_client.clone(), &h).await {
                Ok(s) => s,
                Err(e) => {
                    info!(
                        "[LEAF-PERF][DISPATCH][TCP] connect outbound failed {} -> {} via [{}] in {}ms: {}",
                        &sess.source,
                        &sess.destination,
                        &h.tag(),
                        handshake_start.elapsed().as_millis(),
                        e
                    );
                    log_request(&sess, h.tag(), h.color(), None);
                    return;
                }
            };
        info!(
            "[LEAF-PERF][DISPATCH][TCP] outbound connected {} -> {} via [{}] in {}ms",
            sess.source,
            sess.destination,
            h.tag(),
            handshake_start.elapsed().as_millis()
        );
        let handle_start = tokio::time::Instant::now();
        match TcpOutboundHandler::handle(h.as_ref(), &sess, stream).await {
            Ok(mut rhs) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);
                info!(
                    "[LEAF-PERF][DISPATCH][TCP] handler ready {} -> {} via [{}] handle={}ms handshake_total={}ms",
                    sess.source,
                    sess.destination,
                    h.tag(),
                    handle_start.elapsed().as_millis(),
                    elapsed.as_millis()
                );

                log_request(&sess, h.tag(), h.color(), Some(elapsed.as_millis()));

                #[cfg(feature = "stat")]
                if *crate::option::ENABLE_STATS {
                    rhs = self
                        .stat_manager
                        .write()
                        .await
                        .stat_stream(rhs, sess.clone());
                }

                match common::io::copy_buf_bidirectional_with_timeout(
                    &mut lhs,
                    &mut rhs,
                    *option::LINK_BUFFER_SIZE * 1024,
                    Duration::from_secs(*option::TCP_UPLINK_TIMEOUT),
                    Duration::from_secs(*option::TCP_DOWNLINK_TIMEOUT),
                )
                .await
                {
                    Ok((up_count, down_count)) => {
                        info!(
                            "[LEAF-PERF][DISPATCH][TCP] link done {} <-> {} up={} down={} via [{}] total={}ms",
                            &sess.source,
                            &sess.destination,
                            up_count,
                            down_count,
                            &h.tag(),
                            dispatch_start.elapsed().as_millis()
                        );
                    }
                    Err(e) => {
                        info!(
                            "[LEAF-PERF][DISPATCH][TCP] link error {} <-> {} via [{}] total={}ms: {}",
                            &sess.source,
                            &sess.destination,
                            &h.tag(),
                            dispatch_start.elapsed().as_millis(),
                            e
                        );
                    }
                }
            }
            Err(e) => {
                info!(
                    "[LEAF-PERF][DISPATCH][TCP] handler failed {} -> {} via [{}] in {}ms: {}",
                    &sess.source,
                    &sess.destination,
                    &h.tag(),
                    handle_start.elapsed().as_millis(),
                    e
                );

                log_request(&sess, h.tag(), h.color(), None);

                if let Err(e) = lhs.shutdown().await {
                    debug!(
                        "tcp downlink {} <- {} error: {} [{}]",
                        &sess.source,
                        &sess.destination,
                        e,
                        &h.tag()
                    );
                }
            }
        }
    }

    pub async fn dispatch_udp(&self, mut sess: Session) -> io::Result<Box<dyn OutboundDatagram>> {
        let dispatch_start = tokio::time::Instant::now();
        info!(
            "[LEAF-PERF][DISPATCH][UDP] begin {} -> {}",
            sess.source,
            sess.destination
        );
        let outbound = {
            let route_start = tokio::time::Instant::now();
            let router = self.router.read().await;
            match router.pick_route(&sess).await {
                Ok(tag) => {
                    info!(
                        "[LEAF-PERF][DISPATCH][UDP] picked route [{}] for {} -> {} in {}ms",
                        tag, &sess.source, &sess.destination, route_start.elapsed().as_millis()
                    );
                    tag.to_owned()
                }
                Err(err) => {
                    info!(
                        "[LEAF-PERF][DISPATCH][UDP] pick route failed for {} -> {} in {}ms: {}",
                        &sess.source,
                        &sess.destination,
                        route_start.elapsed().as_millis(),
                        err
                    );
                    if let Some(tag) = self.outbound_manager.read().await.default_handler() {
                        info!(
                            "[LEAF-PERF][DISPATCH][UDP] picked default route [{}] for {} -> {}",
                            tag, &sess.source, &sess.destination
                        );
                        tag
                    } else {
                        warn!("[LEAF-PERF][DISPATCH][UDP] no handler found");
                        return Err(io::Error::new(ErrorKind::Other, "no available handler"));
                    }
                }
            }
        };

        sess.outbound_tag = outbound.clone();

        let h = if let Some(h) = self.outbound_manager.read().await.get(&outbound) {
            h
        } else {
            warn!("[LEAF-PERF][DISPATCH][UDP] handler [{}] not found", outbound);
            return Err(io::Error::new(ErrorKind::Other, "handler not found"));
        };

        let handshake_start = tokio::time::Instant::now();
        info!(
            "[LEAF-PERF][DISPATCH][UDP] connect outbound begin {} -> {} via [{}]",
            sess.source,
            sess.destination,
            h.tag()
        );
        let transport =
            crate::proxy::connect_udp_outbound(&sess, self.dns_client.clone(), &h).await?;
        info!(
            "[LEAF-PERF][DISPATCH][UDP] outbound connected {} -> {} via [{}] in {}ms",
            sess.source,
            sess.destination,
            h.tag(),
            handshake_start.elapsed().as_millis()
        );
        let handle_start = tokio::time::Instant::now();
        match UdpOutboundHandler::handle(h.as_ref(), &sess, transport).await {
            #[allow(unused_mut)]
            Ok(mut d) => {
                let elapsed = tokio::time::Instant::now().duration_since(handshake_start);
                info!(
                    "[LEAF-PERF][DISPATCH][UDP] handler ready {} -> {} via [{}] handle={}ms total={}ms",
                    sess.source,
                    sess.destination,
                    h.tag(),
                    handle_start.elapsed().as_millis(),
                    dispatch_start.elapsed().as_millis()
                );

                log_request(&sess, h.tag(), h.color(), Some(elapsed.as_millis()));

                #[cfg(feature = "stat")]
                if *crate::option::ENABLE_STATS {
                    d = self
                        .stat_manager
                        .write()
                        .await
                        .stat_outbound_datagram(d, sess.clone());
                }

                Ok(d)
            }
            Err(e) => {
                info!(
                    "[LEAF-PERF][DISPATCH][UDP] handler failed {} -> {} via [{}] in {}ms: {}",
                    &sess.source,
                    &sess.destination,
                    &h.tag(),
                    handle_start.elapsed().as_millis(),
                    e
                );
                log_request(&sess, h.tag(), h.color(), None);
                Err(e)
            }
        }
    }
}

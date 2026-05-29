use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::{sink::SinkExt, stream::StreamExt};
#[cfg(windows)]
use lazy_static::lazy_static;
use log::*;
use protobuf::Message;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tokio::sync::Semaphore;
use tun;
use tun::AbstractDevice;

use crate::{
    app::dispatcher::Dispatcher,
    app::fake_dns::{FakeDns, FakeDnsMode},
    app::nat_manager::NatManager,
    app::nat_manager::UdpPacket,
    config::{Inbound, TunInboundSettings},
    option,
    session::{DatagramSource, Network, Session, SocksAddr},
    Runner,
};

fn is_unproxyable_tun_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip == Ipv4Addr::new(224, 0, 0, 252)
                || ip == Ipv4Addr::new(239, 255, 255, 250)
        }
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    }
}

fn is_unproxyable_tun_destination(destination: &SocksAddr) -> bool {
    match destination {
        SocksAddr::Ip(addr) => is_unproxyable_tun_ip(addr.ip()),
        SocksAddr::Domain(domain, _) => domain.is_empty(),
    }
}

use super::netstack;

#[cfg(windows)]
lazy_static! {
    static ref PREWARMED_WINDOWS_TUN: std::sync::Mutex<Option<tun::AsyncDevice>> =
        std::sync::Mutex::new(None);
}

#[cfg(windows)]
static WINDOWS_TUN_RUNTIME_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
struct WindowsTunRuntimeGuard;

#[cfg(windows)]
impl Drop for WindowsTunRuntimeGuard {
    fn drop(&mut self) {
        WINDOWS_TUN_RUNTIME_ACTIVE.store(false, Ordering::SeqCst);
    }
}

fn configure_auto_tun(cfg: &mut tun::Configuration, include_destination: bool) {
    cfg.name(&*option::DEFAULT_TUN_NAME)
        .address(&*option::DEFAULT_TUN_IPV4_ADDR)
        .mtu(1500);

    if include_destination {
        cfg.destination(&*option::DEFAULT_TUN_IPV4_GW);
    }

    #[cfg(windows)]
    {
        use std::net::{IpAddr, Ipv4Addr};
        cfg.metric(1);
        cfg.platform_config(|platform| {
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    platform.wintun_file(dir.join("wintun.dll").into_os_string());
                }
            }
            platform.dns_servers(&[
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ]);
        });
    }

    #[cfg(not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "mipsel",
        target_arch = "mipsel64",
    )))]
    {
        cfg.netmask(&*option::DEFAULT_TUN_IPV4_MASK);
    }

    cfg.up();
}

#[cfg(windows)]
pub fn prewarm_windows_tun() -> Result<()> {
    if WINDOWS_TUN_RUNTIME_ACTIVE.load(Ordering::SeqCst) {
        info!("skip Windows TUN prewarm: runtime TUN is active");
        return Ok(());
    }

    let mut slot = PREWARMED_WINDOWS_TUN
        .lock()
        .map_err(|_| anyhow!("prewarmed Windows TUN mutex poisoned"))?;
    if WINDOWS_TUN_RUNTIME_ACTIVE.load(Ordering::SeqCst) {
        info!("skip Windows TUN prewarm: runtime TUN became active");
        return Ok(());
    }
    if slot.is_some() {
        return Ok(());
    }

    let mut cfg = tun::Configuration::default();
    configure_auto_tun(&mut cfg, false);

    let tun = tun::create_as_async(&cfg).map_err(|e| anyhow!("prewarm tun failed: {}", e))?;
    let index = tun
        .tun_index()
        .map_err(|e| anyhow!("get prewarmed tun index failed: {}", e))?;
    std::env::set_var("LEAF_TUN_INTERFACE_INDEX", index.to_string());
    info!(
        "prewarmed Windows TUN adapter: name={}, index={}",
        tun.tun_name().unwrap_or_default(),
        index
    );

    *slot = Some(tun);
    Ok(())
}

#[cfg(windows)]
pub fn release_prewarmed_windows_tun() {
    if let Ok(mut slot) = PREWARMED_WINDOWS_TUN.lock() {
        if slot.take().is_some() {
            info!("released prewarmed Windows TUN adapter");
        }
    }
}

#[cfg(windows)]
fn take_prewarmed_windows_tun(cfg: &tun::Configuration) -> Result<Option<tun::AsyncDevice>> {
    WINDOWS_TUN_RUNTIME_ACTIVE.store(true, Ordering::SeqCst);

    let Some(mut tun) = PREWARMED_WINDOWS_TUN
        .lock()
        .map_err(|_| anyhow!("prewarmed Windows TUN mutex poisoned"))?
        .take()
    else {
        return Ok(None);
    };

    tun.configure(cfg)
        .map_err(|e| anyhow!("configure prewarmed tun failed: {}", e))?;
    info!(
        "using prewarmed Windows TUN adapter: name={}",
        tun.tun_name().unwrap_or_default()
    );
    Ok(Some(tun))
}

#[cfg(windows)]
fn mark_windows_tun_runtime_active() -> WindowsTunRuntimeGuard {
    WINDOWS_TUN_RUNTIME_ACTIVE.store(true, Ordering::SeqCst);
    WindowsTunRuntimeGuard
}

async fn handle_inbound_stream(
    stream: netstack::TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    inbound_tag: String,
    dispatcher: Arc<Dispatcher>,
    fakedns: Arc<FakeDns>,
) {
    let mut sess = Session {
        network: Network::Tcp,
        source: local_addr,
        local_addr: remote_addr.clone(),
        destination: SocksAddr::Ip(remote_addr.clone()),
        inbound_tag: inbound_tag,
        ..Default::default()
    };
    // Whether to override the destination according to Fake DNS.
    log::debug!("TUN TCP connection: {} -> {}", local_addr, remote_addr);
    if is_unproxyable_tun_ip(remote_addr.ip()) {
        log::debug!(
            "Dropping unproxyable TUN TCP connection: {} -> {}",
            local_addr,
            remote_addr
        );
        return;
    }
    if fakedns.is_fake_ip(&remote_addr.ip()).await {
        if let Some(domain) = fakedns.query_domain(&remote_addr.ip()).await {
            if domain.is_empty() {
                log::debug!(
                    "Dropping TUN TCP connection with empty fake DNS domain: {} -> {}",
                    local_addr,
                    remote_addr
                );
                return;
            }
            sess.destination = SocksAddr::Domain(domain, remote_addr.port());
        } else {
            // Although requests targeting fake IPs are assumed
            // never happen in real network traffic, which are
            // likely caused by poisoned DNS cache records, we
            // still have a chance to sniff the request domain
            // for TLS traffic in dispatcher.
            if remote_addr.port() != 443 {
                log::debug!(
                    "No paired domain found for this fake IP: {}, connection is rejected.",
                    &remote_addr.ip()
                );
                return;
            }
        }
    }
    dispatcher.dispatch_tcp(sess, stream).await;
}

async fn handle_inbound_datagram(
    socket: Box<netstack::UdpSocket>,
    inbound_tag: String,
    nat_manager: Arc<NatManager>,
    fakedns: Arc<FakeDns>,
) {
    // The socket to receive/send packets from/to the netstack.
    let (ls, mut lr) = socket.split();
    let ls = Arc::new(ls);

    // The channel for sending back datagrams from NAT manager to netstack.
    let (l_tx, mut l_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) = tokio_channel(32);

    // Receive datagrams from NAT manager and send back to netstack.
    let fakedns_cloned = fakedns.clone();
    let ls_cloned = ls.clone();
    tokio::spawn(async move {
        while let Some(pkt) = l_rx.recv().await {
            let src_addr = match pkt.src_addr {
                SocksAddr::Ip(a) => a,
                SocksAddr::Domain(domain, port) => {
                    if let Some(ip) = fakedns_cloned.query_fake_ip(&domain).await {
                        SocketAddr::new(ip, port)
                    } else {
                        warn!(
                            "Received datagram with source address {}:{} without paired fake IP found.",
                            &domain, &port
                        );
                        continue;
                    }
                }
            };
            if let Err(e) = ls_cloned.send_to(&pkt.data[..], &src_addr, &pkt.dst_addr.must_ip()) {
                warn!("A packet failed to send to the netstack: {}", e);
            }
        }
    });

    // Accept datagrams from netstack and send to NAT manager.
    loop {
        match lr.recv_from().await {
            Err(e) => {
                log::warn!("Failed to accept a datagram from netstack: {}", e);
            }
            Ok((data, src_addr, dst_addr)) => {
                // Fake DNS logic.
                if dst_addr.port() == 53 {
                    log::debug!("TUN UDP DNS packet: {} -> {}", src_addr, dst_addr);
                    match fakedns.generate_fake_response(&data).await {
                        Ok(resp) => {
                            if let Err(e) = ls.send_to(resp.as_ref(), &dst_addr, &src_addr) {
                                warn!("A packet failed to send to the netstack: {}", e);
                            }
                            continue;
                        }
                        Err(err) => {
                            trace!("generate fake ip failed: {}", err);
                        }
                    }
                }

                // Whether to override the destination according to Fake DNS.
                //
                // WARNING
                //
                // This allows datagram to have a domain name as destination,
                // but real UDP traffic are sent with IP address only. If the
                // outbound for this datagram is a direct one, the outbound
                // would resolve the domain to IP address before sending out
                // the datagram. If the outbound is a proxy one, it would
                // require a proxy server with the ability to handle datagrams
                // with domain name destination, leaf itself of course supports
                // this feature very well.
                if is_unproxyable_tun_ip(dst_addr.ip()) {
                    log::debug!(
                        "Dropping unproxyable TUN UDP datagram: {} -> {}",
                        src_addr,
                        dst_addr
                    );
                    continue;
                }

                let dst_addr = if fakedns.is_fake_ip(&dst_addr.ip()).await {
                    if let Some(domain) = fakedns.query_domain(&dst_addr.ip()).await {
                        SocksAddr::Domain(domain, dst_addr.port())
                    } else {
                        log::debug!(
                            "No paired domain found for this fake IP: {}, datagram is rejected.",
                            &dst_addr.ip()
                        );
                        continue;
                    }
                } else {
                    SocksAddr::Ip(dst_addr)
                };

                if is_unproxyable_tun_destination(&dst_addr) {
                    log::debug!(
                        "Dropping unproxyable TUN UDP datagram: {} -> {}",
                        src_addr,
                        dst_addr
                    );
                    continue;
                }

                let dgram_src = DatagramSource::new(src_addr, None);
                let pkt = UdpPacket::new(data, SocksAddr::Ip(src_addr), dst_addr);
                nat_manager
                    .send(None, &dgram_src, &inbound_tag, &l_tx, pkt)
                    .await;
            }
        }
    }
}

pub fn new(
    inbound: Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> Result<Runner> {
    let settings = TunInboundSettings::parse_from_bytes(&inbound.settings)?;
    let can_use_prewarmed_windows_tun = settings.fd < 0 && settings.auto;

    let mut cfg = tun::Configuration::default();
    if settings.fd >= 0 {
        cfg.raw_fd(settings.fd);
    } else if settings.auto {
        configure_auto_tun(&mut cfg, true);
    } else {
        cfg.name(settings.name)
            .address(settings.address)
            .destination(settings.gateway)
            .mtu(settings.mtu.try_into().unwrap_or(1500));

        #[cfg(not(any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "mipsel",
            target_arch = "mipsel64",
        )))]
        {
            cfg.netmask(settings.netmask);
        }

        cfg.up();
    }

    // FIXME it's a bad design to have 2 lists in config while we need only one
    let fake_dns_exclude = settings.fake_dns_exclude;
    let fake_dns_include = settings.fake_dns_include;
    if !fake_dns_exclude.is_empty() && !fake_dns_include.is_empty() {
        return Err(anyhow!(
            "fake DNS run in either include mode or exclude mode"
        ));
    }
    let (fake_dns_mode, fake_dns_filters) = if !fake_dns_include.is_empty() {
        (FakeDnsMode::Include, fake_dns_include)
    } else {
        (FakeDnsMode::Exclude, fake_dns_exclude)
    };

    #[cfg(windows)]
    let windows_tun_runtime_guard = if can_use_prewarmed_windows_tun {
        Some(mark_windows_tun_runtime_active())
    } else {
        None
    };
    #[cfg(windows)]
    let mut tun = if can_use_prewarmed_windows_tun {
        match take_prewarmed_windows_tun(&cfg)? {
            Some(tun) => tun,
            None => tun::create_as_async(&cfg).map_err(|e| anyhow!("create tun failed: {}", e))?,
        }
    } else {
        tun::create_as_async(&cfg).map_err(|e| anyhow!("create tun failed: {}", e))?
    };
    #[cfg(not(windows))]
    let tun = tun::create_as_async(&cfg).map_err(|e| anyhow!("create tun failed: {}", e))?;
    #[cfg(windows)]
    {
        let index = tun
            .tun_index()
            .map_err(|e| anyhow!("get tun index failed: {}", e))?;
        std::env::set_var("LEAF_TUN_INTERFACE_INDEX", index.to_string());
        info!(
            "created Windows TUN adapter: name={}, index={}",
            tun.tun_name().unwrap_or_default(),
            index
        );
    }

    if settings.auto {
        assert!(settings.fd == -1, "tun-auto is not compatible with tun-fd");
    }

    Ok(Box::pin(async move {
        #[cfg(windows)]
        let _windows_tun_runtime_guard = windows_tun_runtime_guard;

        let fakedns = Arc::new(FakeDns::new(fake_dns_mode));
        for filter in fake_dns_filters.into_iter() {
            fakedns.add_filter(filter).await;
        }

        let inbound_tag = inbound.tag.clone();
        let framed = tun.into_framed();
        let (mut tun_sink, mut tun_stream) = framed.split();
        let (stack, mut tcp_listener, udp_socket) = netstack::NetStack::new();
        let (mut stack_sink, mut stack_stream) = stack.split();

        let mut futs: Vec<Runner> = Vec::new();

        // Reads packet from stack and sends to TUN.
        futs.push(Box::pin(async move {
            while let Some(pkt) = stack_stream.next().await {
                if let Ok(pkt) = pkt {
                    tun_sink.send(pkt).await.unwrap();
                }
            }
        }));

        // Reads packet from TUN and sends to stack.
        futs.push(Box::pin(async move {
            while let Some(pkt) = tun_stream.next().await {
                if let Ok(pkt) = pkt {
                    stack_sink.send(pkt).await.unwrap();
                }
            }
        }));

        // Extracts TCP connections from stack and sends them to the dispatcher.
        let inbound_tag_cloned = inbound_tag.clone();
        let fakedns_cloned = fakedns.clone();
        let tcp_dispatcher = dispatcher.clone();
        futs.push(Box::pin(async move {
            let tcp_slots = Arc::new(Semaphore::new(*option::TUN_TCP_CONCURRENCY));
            while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
                let permit = match tcp_slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        log::warn!(
                            "TUN TCP concurrency full, closing {} -> {}",
                            local_addr,
                            remote_addr
                        );
                        tokio::spawn(async move {
                            let mut stream = stream;
                            let _ = stream.shutdown().await;
                        });
                        continue;
                    }
                };
                let inbound_tag = inbound_tag_cloned.clone();
                let dispatcher = tcp_dispatcher.clone();
                let fakedns = fakedns_cloned.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_inbound_stream(
                        stream,
                        local_addr,
                        remote_addr,
                        inbound_tag,
                        dispatcher,
                        fakedns,
                    )
                    .await;
                });
            }
        }));

        // Receive and send UDP packets between netstack and NAT manager. The NAT
        // manager would maintain UDP sessions and send them to the dispatcher.
        futs.push(Box::pin(async move {
            handle_inbound_datagram(udp_socket, inbound_tag, nat_manager, fakedns.clone()).await;
        }));

        info!("start tun inbound");
        futures::future::select_all(futs).await;
    }))
}

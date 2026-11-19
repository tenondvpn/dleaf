use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;

use lazy_static::lazy_static;

/// 因 `TUN_TCP_CONCURRENCY` 已满而被直接关闭的 TUN TCP 连接累计数。
/// iOS / macOS 的 leaf 日志是空实现（`mobile/logger.rs` 的 `log_out`），那条 warn 看不到，
/// 所以另外用计数器暴露给宿主（`leaf::tun_tcp_rejected()`）。
pub static TUN_TCP_REJECTED: AtomicU64 = AtomicU64::new(0);

/// TUN 入口各阶段的诊断计数：utun 读到多少包、lwip 吞包是否变慢、TCP 接受/在途多少、
/// UDP 与 DNS 收到多少。全部是原子计数，不改变数据路径。卡顿时用它判断包停在哪一级。
/// 宿主通过 `leaf::tun_stats()` 取 JSON；带 `_max_ms` 的字段读出后清零（只表示上一个间隔）。
pub mod tun_stats {
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};

    pub static PKT_IN: AtomicU64 = AtomicU64::new(0); // utun -> lwip 的包
    pub static BYTES_IN: AtomicU64 = AtomicU64::new(0);
    pub static PKT_OUT: AtomicU64 = AtomicU64::new(0); // lwip -> utun 的包
    pub static BYTES_OUT: AtomicU64 = AtomicU64::new(0);
    pub static IN_SEND_MAX_MS: AtomicU64 = AtomicU64::new(0); // 把包交给 lwip 的最长耗时
    pub static IN_SEND_SLOW: AtomicU64 = AtomicU64::new(0); // 其中 > 100ms 的次数
    pub static OUT_SEND_MAX_MS: AtomicU64 = AtomicU64::new(0); // 把包写回 utun 的最长耗时
    pub static OUT_SEND_SLOW: AtomicU64 = AtomicU64::new(0);
    pub static TCP_ACCEPTED: AtomicU64 = AtomicU64::new(0); // lwip 接受的 TCP 连接
    pub static TCP_ACTIVE: AtomicI64 = AtomicI64::new(0); // 在途（已接受、尚未结束）
    pub static UDP_UP: AtomicU64 = AtomicU64::new(0); // 从 lwip 收到的 UDP 数据报
    pub static UDP_DOWN: AtomicU64 = AtomicU64::new(0); // 回给 lwip 的 UDP 数据报
    pub static DNS: AtomicU64 = AtomicU64::new(0); // 其中目的端口 53 的
    pub static DNS_FAKE: AtomicU64 = AtomicU64::new(0); // 生成了假响应
    pub static DNS_ERR: AtomicU64 = AtomicU64::new(0); // 假响应失败（转为普通 UDP）
    pub static DNS_MAX_MS: AtomicU64 = AtomicU64::new(0); // 生成假响应的最长耗时
    pub static UDP_DROP443: AtomicU64 = AtomicU64::new(0); // 因 DROP_QUIC 开关被丢弃的 UDP 443 数据报

    const SLOW_MS: u64 = 100;

    pub fn note_in_send(ms: u64) {
        IN_SEND_MAX_MS.fetch_max(ms, Relaxed);
        if ms > SLOW_MS {
            IN_SEND_SLOW.fetch_add(1, Relaxed);
        }
    }

    pub fn note_out_send(ms: u64) {
        OUT_SEND_MAX_MS.fetch_max(ms, Relaxed);
        if ms > SLOW_MS {
            OUT_SEND_SLOW.fetch_add(1, Relaxed);
        }
    }

    pub fn json() -> String {
        format!(
            concat!(
                "{{\"pkt_in\":{},\"bytes_in\":{},\"pkt_out\":{},\"bytes_out\":{},",
                "\"in_send_max_ms\":{},\"in_send_slow\":{},\"out_send_max_ms\":{},\"out_send_slow\":{},",
                "\"tcp_acc\":{},\"tcp_act\":{},\"udp_up\":{},\"udp_down\":{},",
                "\"dns\":{},\"dns_fake\":{},\"dns_err\":{},\"dns_max_ms\":{},\"udp_drop443\":{}}}"
            ),
            PKT_IN.load(Relaxed),
            BYTES_IN.load(Relaxed),
            PKT_OUT.load(Relaxed),
            BYTES_OUT.load(Relaxed),
            IN_SEND_MAX_MS.swap(0, Relaxed),
            IN_SEND_SLOW.load(Relaxed),
            OUT_SEND_MAX_MS.swap(0, Relaxed),
            OUT_SEND_SLOW.load(Relaxed),
            TCP_ACCEPTED.load(Relaxed),
            TCP_ACTIVE.load(Relaxed),
            UDP_UP.load(Relaxed),
            UDP_DOWN.load(Relaxed),
            DNS.load(Relaxed),
            DNS_FAKE.load(Relaxed),
            DNS_ERR.load(Relaxed),
            DNS_MAX_MS.swap(0, Relaxed),
            UDP_DROP443.load(Relaxed),
        )
    }
}

// Gets an environment variable by a key and parses as type `T` or returns
// the provided default value.
fn get_env_var_or<T>(key: &str, default: T) -> T
where
    T: FromStr,
{
    if let Ok(v) = env::var(key) {
        if let Ok(v) = v.parse::<T>() {
            return v;
        }
    }
    default
}

#[cfg(target_os = "ios")]
lazy_static! {
    /// Maximum number of proxy outbound TCP connections allowed at the same time.
    pub static ref ENDPOINT_TCP_CONCURRENCY: usize = {
        get_env_var_or("ENDPOINT_TCP_CONCURRENCY", 45)
    };

    /// Maximum number of direct outbound TCP connections allowed at the same time.
    pub static ref DIRECT_TCP_CONCURRENCY: usize = {
        get_env_var_or("DIRECT_TCP_CONCURRENCY", 64)
    };

    /// Maximum number of TUN TCP connections dispatched at the same time.
    pub static ref TUN_TCP_CONCURRENCY: usize = {
        get_env_var_or("TUN_TCP_CONCURRENCY", 64)
    };

    /// DNS cache size in the built-in DNS client.
    pub static ref DNS_CACHE_SIZE: usize = {
        get_env_var_or("DNS_CACHE_SIZE", 64)
    };
}

#[cfg(not(target_os = "ios"))]
lazy_static! {
    /// Maximum number of proxy outbound TCP connections allowed at the same time.
    pub static ref ENDPOINT_TCP_CONCURRENCY: usize = {
        get_env_var_or("ENDPOINT_TCP_CONCURRENCY", 1024)
    };

    /// Maximum number of direct outbound TCP connections allowed at the same time.
    pub static ref DIRECT_TCP_CONCURRENCY: usize = {
        get_env_var_or("DIRECT_TCP_CONCURRENCY", 1024)
    };

    /// Maximum number of TUN TCP connections dispatched at the same time.
    pub static ref TUN_TCP_CONCURRENCY: usize = {
        get_env_var_or("TUN_TCP_CONCURRENCY", 512)
    };

    /// DNS cache size in the built-in DNS client.
    pub static ref DNS_CACHE_SIZE: usize = {
        get_env_var_or("DNS_CACHE_SIZE", 512)
    };
}

lazy_static! {
    /// 实验开关：丢弃应用发往 UDP 443 的数据报（YouTube/Chrome 的 QUIC），应用会回落到 TCP。
    /// 环境变量 DROP_QUIC=true 打开，默认关闭；其余 UDP（DNS、语音等）不受影响。
    /// 数据报在 TUN 入口就被丢弃，不会进入 NAT 会话，也不会经连接器发往 Hysteria2。
    pub static ref DROP_QUIC: bool = get_env_var_or("DROP_QUIC", false);
}

#[cfg(feature = "stat")]
lazy_static! {
    pub static ref ENABLE_STATS: bool = get_env_var_or("ENABLE_STATS", false);
}

lazy_static! {
    pub static ref HTTP_USER_AGENT: String = {
        get_env_var_or(
            "HTTP_USER_AGENT",
            get_env_var_or("USER_AGENT", "".to_string()), // legacy support
        )
    };

    // The purpose is not to propagate the header, but to extract the forwarded
    // source IP. Expects only comma separated IP list and only the first IP is
    // taken as the forwarded source. Having this value customizable would benefit
    // in case you don't trust the X-Forwarded-For header but there is another header
    // which you can trust, for example the CF-Connecting-IP provided by Cloudflare.
    pub static ref HTTP_FORWARDED_HEADER: String = {
        get_env_var_or("HTTP_FORWARDED_HEADER", "X-Forwarded-For".to_string())
    };

    pub static ref LOG_CONSOLE_OUT: bool = {
        get_env_var_or("LOG_CONSOLE_OUT", false)
    };

    pub static ref LOG_NO_COLOR: bool = {
        get_env_var_or("LOG_NO_COLOR", false)
    };

    /// Uplink timeout after downlink EOF.
    pub static ref TCP_UPLINK_TIMEOUT: u64 = {
        get_env_var_or("TCP_UPLINK_TIMEOUT", 10)
    };

    /// Downlink timeout after uplink EOF.
    pub static ref TCP_DOWNLINK_TIMEOUT: u64 = {
        get_env_var_or("TCP_DOWNLINK_TIMEOUT", 10)
    };

    /// Buffer size for uplink and downlink connections, in KB.
    /// 64 KB covers a full TCP window per read/write cycle; the old 2 KB
    /// value throttled downloads by forcing thousands of tiny syscalls.
    pub static ref LINK_BUFFER_SIZE: usize = {
        get_env_var_or("LINK_BUFFER_SIZE", 64)
    };

    /// Buffer size for UDP datagrams receiving/sending, in KB.
    pub static ref DATAGRAM_BUFFER_SIZE: usize = {
        get_env_var_or("DATAGRAM_BUFFER_SIZE", 16)
    };

    pub static ref OUTBOUND_DIAL_TIMEOUT: u64 = {
        get_env_var_or("OUTBOUND_DIAL_TIMEOUT", 4)
    };

    /// Maximum outbound dial concurrency.
    pub static ref OUTBOUND_DIAL_CONCURRENCY: usize = {
        get_env_var_or("OUTBOUND_DIAL_CONCURRENCY", 1)
    };

    pub static ref ASSET_LOCATION: String = {
        let mut file = std::env::current_exe().unwrap();
        file.pop();
        get_env_var_or("ASSET_LOCATION", file.to_str().unwrap().to_string())
    };

    pub static ref CACHE_LOCATION: String = {
        get_env_var_or("CACHE_LOCATION", "".to_string())
    };

    pub static ref API_LISTEN: String = {
        get_env_var_or("API_LISTEN", "".to_string())
    };

    pub static ref ENABLE_IPV6: bool = {
        get_env_var_or("ENABLE_IPV6", false)
    };

    pub static ref PREFER_IPV6: bool = {
        get_env_var_or("PREFER_IPV6", false)
    };

    pub static ref UNSPECIFIED_BIND_ADDR: SocketAddr = {
        let default =  if *ENABLE_IPV6 {
            "[::]:0".to_string().parse().unwrap()
        } else {
            "0.0.0.0:0".to_string().parse().unwrap()
        };
        get_env_var_or("UNSPECIFIED_BIND_ADDR", default)
    };

    pub static ref OUTBOUND_BINDS: Vec<crate::proxy::OutboundBind> = {
        outbound_binds()
    };

    /// Sets the RPC service endpoint for protecting outbound sockets on Android to
    /// avoid infinite loop. The `path` is treated as a Unix domain socket endpoint.
    /// The RPC service simply listens for incoming connections, reads an int32 on
    /// each connection, treats it as the file descriptor to protect, writes back 0
    /// on success.
    pub static ref SOCKET_PROTECT_PATH: String = {
        get_env_var_or("SOCKET_PROTECT_PATH", "".to_string())
    };

    pub static ref SOCKET_PROTECT_SERVER: Option<SocketAddr> = {
        get_env_var_or("SOCKET_PROTECT_SERVER", "".to_string()).parse().ok()
    };

    pub static ref GATEWAY_MODE: bool = {
        get_env_var_or("GATEWAY_MODE", false)
    };

    /// UDP session timeout. A UDP session shall be terminated if there are no
    /// activities in this period. The timeouts are observed only when a check
    /// is happened.
    pub static ref UDP_SESSION_TIMEOUT: u64 = {
        get_env_var_or("UDP_SESSION_TIMEOUT", 30)
    };

    /// UDP session timeout check interval. The interval to check for UDP session
    /// timeouts.
    pub static ref UDP_SESSION_TIMEOUT_CHECK_INTERVAL: u64 = {
        get_env_var_or("UDP_SESSION_TIMEOUT_CHECK_INTERVAL", 10)
    };

    /// Maximum retries for a specific DNS query for the built-in DNS client.
    pub static ref MAX_DNS_RETRIES: usize = {
        get_env_var_or("MAX_DNS_RETRIES", 4)
    };

    /// Timeout for a DNS query for the built-in DNS client.
    pub static ref DNS_TIMEOUT: u64 = {
        get_env_var_or("DNS_TIMEOUT", 4)
    };

    pub static ref DEFAULT_TUN_NAME: String = {
        get_env_var_or("DEFAULT_TUN_NAME", "utun233".to_string())
    };

    pub static ref DEFAULT_TUN_IPV4_ADDR: String = {
        get_env_var_or("DEFAULT_TUN_IPV4_ADDR", "240.255.0.2".to_string())
    };

    pub static ref DEFAULT_TUN_IPV4_GW: String = {
        get_env_var_or("DEFAULT_TUN_IPV4_GW", "240.255.0.1".to_string())
    };

    pub static ref DEFAULT_TUN_IPV4_MASK: String = {
        get_env_var_or("DEFAULT_TUN_IPV4_MASK", "255.255.255.0".to_string())
    };

    /// DNS servers assigned to the auto-created TUN adapter.  These must be
    /// reachable from the physical NIC, because the TUN captures all traffic but
    /// the adapter's DNS lookups are routed to the bypass rules the embedder
    /// installs.  Defaults to China-reachable resolvers rather than 8.8.8.8,
    /// which many networks blackhole.
    pub static ref DEFAULT_TUN_DNS: String = {
        get_env_var_or("DEFAULT_TUN_DNS", "223.5.5.5,114.114.114.114".to_string())
    };

    pub static ref DEFAULT_TUN_IPV6_ADDR: String = {
        get_env_var_or("DEFAULT_TUN_IPV6_ADDR", "2001:2::2".to_string())
    };

    pub static ref DEFAULT_TUN_IPV6_GW: String = {
        get_env_var_or("DEFAULT_TUN_IPV6_GW", "2001:2::1".to_string())
    };

    pub static ref DEFAULT_TUN_IPV6_PREFIXLEN: i32 = {
        get_env_var_or("DEFAULT_TUN_IPV6_PREFIXLEN", 64)
    };

    /// When true, dleaf routes same-country destinations to PAC_DIRECT_TAG before
    /// config rules, bypassing VPN / p2pconnector outbounds.
    pub static ref PAC_MODE: bool = {
        get_env_var_or("PAC_MODE", false)
    };

    /// ISO country code for the client (e.g. CN, US). Required when PAC_MODE is on.
    pub static ref LOCAL_COUNTRY: String = {
        get_env_var_or("LOCAL_COUNTRY", "".to_string())
    };

    /// Outbound tag used for PAC same-country direct forwarding.
    pub static ref PAC_DIRECT_TAG: String = {
        get_env_var_or("PAC_DIRECT_TAG", "Direct".to_string())
    };
}

pub fn outbound_binds() -> Vec<crate::proxy::OutboundBind> {
    let binds = get_env_var_or("OUTBOUND_INTERFACE", "0.0.0.0,::".to_string());
    let mut outbound_binds = Vec::new();
    for item in binds.split(',').map(str::trim) {
        if item.is_empty() {
            continue;
        }
        if let Ok(addr) = crate::common::net::parse_bind_addr(item) {
            outbound_binds.push(crate::proxy::OutboundBind::Ip(addr));
        } else {
            outbound_binds.push(crate::proxy::OutboundBind::Interface(item.to_owned()));
        }
    }
    outbound_binds
}

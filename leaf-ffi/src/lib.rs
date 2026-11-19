use std::{ffi::CStr, os::raw::c_char};

// Registers a process-wide Rust panic hook that writes panic info to
// %TEMP%\fkey_panic_<pid>.log before abort() terminates the process.
// With panic="abort", abort() bypasses C++ atexit/SEH so without this hook
// the crash leaves no evidence at all.
fn install_panic_hook() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let pid = std::process::id();
            let mut path = std::env::temp_dir();
            path.push(format!("fkey_panic_{}.log", pid));
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true).append(true).open(&path)
            {
                use std::io::Write;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let _ = writeln!(f, "[{now}] RUST PANIC pid={pid}");
                let _ = writeln!(f, "  {info}");
                if let Some(loc) = info.location() {
                    let _ = writeln!(
                        f, "  at {}:{}:{}",
                        loc.file(), loc.line(), loc.column()
                    );
                }
            }
        }));
    });
}

/// No error.
pub const ERR_OK: i32 = 0;
/// Config path error.
pub const ERR_CONFIG_PATH: i32 = 1;
/// Config parsing error.
pub const ERR_CONFIG: i32 = 2;
/// IO error.
pub const ERR_IO: i32 = 3;
/// Config file watcher error.
pub const ERR_WATCHER: i32 = 4;
/// Async channel send error.
pub const ERR_ASYNC_CHANNEL_SEND: i32 = 5;
/// Sync channel receive error.
pub const ERR_SYNC_CHANNEL_RECV: i32 = 6;
/// Runtime manager error.
pub const ERR_RUNTIME_MANAGER: i32 = 7;
/// No associated config file.
pub const ERR_NO_CONFIG_FILE: i32 = 8;

fn to_errno(e: leaf::Error) -> i32 {
    match e {
        leaf::Error::Config(..) => ERR_CONFIG,
        leaf::Error::NoConfigFile => ERR_NO_CONFIG_FILE,
        leaf::Error::Io(..) => ERR_IO,
        #[cfg(feature = "auto-reload")]
        leaf::Error::Watcher(..) => ERR_WATCHER,
        leaf::Error::AsyncChannelSend(..) => ERR_ASYNC_CHANNEL_SEND,
        leaf::Error::SyncChannelRecv(..) => ERR_SYNC_CHANNEL_RECV,
        leaf::Error::RuntimeManager => ERR_RUNTIME_MANAGER,
    }
}

/// Starts leaf with options, on a successful start this function blocks the current
/// thread.
///
/// @note This is not a stable API, parameters will change from time to time.
///
/// @param rt_id A unique ID to associate this leaf instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @param auto_reload Enabls auto reloading when config file changes are detected,
///                    takes effect only when the "auto-reload" feature is enabled.
/// @param multi_thread Whether to use a multi-threaded runtime.
/// @param auto_threads Sets the number of runtime worker threads automatically,
///                     takes effect only when multi_thread is true.
/// @param threads Sets the number of runtime worker threads, takes effect when
///                     multi_thread is true, but can be overridden by auto_threads.
/// @param stack_size Sets stack size of the runtime worker threads, takes effect when
///                   multi_thread is true.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[no_mangle]
pub extern "C" fn leaf_run_with_options(
    rt_id: u16,
    config_path: *const c_char,
    auto_reload: bool, // requires this parameter anyway
    multi_thread: bool,
    auto_threads: bool,
    threads: i32,
    stack_size: i32,
) -> i32 {
    install_panic_hook();
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        if let Err(e) = leaf::util::run_with_options(
            rt_id,
            config_path.to_string(),
            #[cfg(feature = "auto-reload")]
            auto_reload,
            multi_thread,
            auto_threads,
            threads as usize,
            stack_size as usize,
        ) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Starts leaf with a single-threaded runtime, on a successful start this function
/// blocks the current thread.
///
/// @param rt_id A unique ID to associate this leaf instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[no_mangle]
pub extern "C" fn leaf_run(rt_id: u16, config_path: *const c_char) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        let opts = leaf::StartOptions {
            config: leaf::Config::File(config_path.to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: leaf::RuntimeOption::SingleThread,
        };
        if let Err(e) = leaf::start(rt_id, opts) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

#[no_mangle]
pub extern "C" fn get_status() -> *mut c_char{
    let c_str_song = std::ffi::CString::new(leaf::get_status()).unwrap();
    c_str_song.into_raw()
    //std::ffi::CString::new(leaf::get_status().as_str()).unwrap().as_ptr();
}

fn json_to_c(json: String) -> *mut c_char {
    std::ffi::CString::new(json.replace('\0', ""))
        .unwrap_or_default()
        .into_raw()
}

/// Which outbound the running leaf picks for "host:port,host:port,..." (nothing is dialed).
/// Returns JSON (see leaf::route_probe); free it with free_status.
#[no_mangle]
pub extern "C" fn leaf_route_probe(targets: *const c_char) -> *mut c_char {
    let parsed: Vec<(String, u16)> = unsafe { targets.as_ref() }
        .and_then(|_| unsafe { CStr::from_ptr(targets).to_str().ok() })
        .unwrap_or("")
        .split(',')
        .filter_map(|item| {
            let (host, port) = item.trim().rsplit_once(':')?;
            let port = port.parse::<u16>().ok()?;
            if host.is_empty() { None } else { Some((host.to_string(), port)) }
        })
        .collect();
    json_to_c(leaf::route_probe(&parsed))
}

/// Per-server DNS results of the running leaf for `host`. Returns JSON (see leaf::dns_probe);
/// free it with free_status.
#[no_mangle]
pub extern "C" fn leaf_dns_probe(host: *const c_char) -> *mut c_char {
    let host = unsafe { host.as_ref() }
        .and_then(|_| unsafe { CStr::from_ptr(host).to_str().ok() })
        .unwrap_or("")
        .trim()
        .to_string();
    json_to_c(leaf::dns_probe(&host))
}

#[no_mangle]
pub extern "C" fn free_status(s: *mut c_char) {
    unsafe {
        if s.is_null() { return }
        std::ffi::CString::from_raw(s)
    };
}

#[no_mangle]
pub extern "C" fn set_pk(s: *const c_char) {
    if let Ok(pk_str) = unsafe { CStr::from_ptr(s).to_str() } {
        leaf::set_pk(pk_str.to_string());
    }
}

#[no_mangle]
pub extern "C" fn set_pk_hash(s: *const c_char) {
    if let Ok(pk_hash) = unsafe { CStr::from_ptr(s).to_str() } {
        leaf::set_pk_hash(pk_hash.to_string());
    }
}

/// p2p-ss mode: force the shadowsocks outbound to encrypt (ShadowedStream) even
/// when the via_connector plaintext suffix is set, so the route node relays
/// ENCRYPTED ss to the vpn node's ss port. Mirrors the Android JNI setP2pSs.
#[no_mangle]
pub extern "C" fn set_p2p_ss(enabled: i32) {
    leaf::set_p2p_ss(enabled != 0);
}

/// Reloads DNS servers, outbounds and routing rules from the config file.
///
/// @param rt_id The ID of the leaf instance to reload.
///
/// @return Returns ERR_OK on success.
#[no_mangle]
pub extern "C" fn leaf_reload(rt_id: u16) -> i32 {
    if let Err(e) = leaf::reload(rt_id) {
        return to_errno(e);
    }
    ERR_OK
}

/// Shuts down leaf.
///
/// @param rt_id The ID of the leaf instance to reload.
///
/// @return Returns true on success, false otherwise.
#[no_mangle]
pub extern "C" fn leaf_shutdown(rt_id: u16) -> bool {
    leaf::shutdown(rt_id)
}

/// Returns whether a leaf runtime instance is active.
#[no_mangle]
pub extern "C" fn leaf_is_running(rt_id: u16) -> bool {
    leaf::is_running(rt_id)
}

/// Pre-creates the Windows TUN session so a later leaf_run can reuse it.
///
/// This does not start leaf routing. It only holds the adapter/session open
/// until leaf_run consumes it or leaf_release_prewarmed_tun drops it.
#[cfg(all(feature = "default-ring", target_os = "windows"))]
#[no_mangle]
pub extern "C" fn leaf_prewarm_tun() -> i32 {
    if let Err(e) = leaf::proxy::tun::inbound::prewarm_windows_tun() {
        eprintln!("leaf_prewarm_tun failed: {}", e);
        return ERR_IO;
    }
    ERR_OK
}

#[cfg(not(all(feature = "default-ring", target_os = "windows")))]
#[no_mangle]
pub extern "C" fn leaf_prewarm_tun() -> i32 {
    ERR_OK
}

/// Releases a pre-created Windows TUN session if leaf_run has not consumed it.
#[cfg(all(feature = "default-ring", target_os = "windows"))]
#[no_mangle]
pub extern "C" fn leaf_release_prewarmed_tun() {
    leaf::proxy::tun::inbound::release_prewarmed_windows_tun();
}

#[cfg(not(all(feature = "default-ring", target_os = "windows")))]
#[no_mangle]
pub extern "C" fn leaf_release_prewarmed_tun() {}

/// Tests the configuration.
///
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return Returns ERR_OK on success, i.e no syntax error.
#[no_mangle]
pub extern "C" fn leaf_test_config(config_path: *const c_char) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        if let Err(e) = leaf::test_config(&config_path) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

fn into_c_string(s: String) -> *mut c_char {
    // An interior NUL would make CString::new fail; strip it instead of panicking across FFI.
    std::ffi::CString::new(s.replace('\0', ""))
        .unwrap_or_default()
        .into_raw()
}

fn from_c_str(s: *const c_char) -> Option<String> {
    if s.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(s).to_str().ok().map(str::to_string) }
}

/// 忘记某个 vpn 节点的握手状态（对应 Android 的 clearNode）。节点被换下后可能再被换回，
/// 到那时服务端可能已忘记本客户端，所以必须重新发送完整密钥。返回 1 表示清掉了状态，0 表示没有。
#[no_mangle]
pub extern "C" fn leaf_clear_node(ip: *const c_char) -> i32 {
    match from_c_str(ip) {
        Some(ip) if !ip.is_empty() => {
            if leaf::clear_node(&ip) { 1 } else { 0 }
        }
        _ => 0,
    }
}

/// 累计下载 / 上传字节（出站流量，单调递增）。外部用相邻两次的差除以间隔得到实时速率。
/// 成功返回 0 并写入两个指针；`stat` feature 未启用时两者恒为 0。
#[no_mangle]
pub extern "C" fn leaf_traffic_bytes(down: *mut u64, up: *mut u64) -> i32 {
    if down.is_null() || up.is_null() {
        return -1;
    }
    let (d, u) = leaf::traffic_bytes();
    unsafe {
        *down = d;
        *up = u;
    }
    0
}

/// 因 TUN TCP 并发上限（iOS 默认 64）已满而被直接关闭的连接累计数，单调递增。
/// 宿主用相邻两次的差判断"并发上限是不是瓶颈"。
#[no_mangle]
pub extern "C" fn leaf_tun_tcp_rejected() -> u64 {
    leaf::tun_tcp_rejected()
}

/// TUN 入口各阶段的诊断计数（JSON）：utun 读写包数、lwip 收包是否变慢、TCP 接受/在途、UDP/DNS 数。
/// 用 `free_status` 释放返回值。
#[no_mangle]
pub extern "C" fn leaf_tun_stats() -> *mut c_char {
    into_c_string(leaf::tun_stats())
}

/// Node list as JSON. Release the result with `free_status`.
#[no_mangle]
pub extern "C" fn get_nodes() -> *mut c_char {
    into_c_string(leaf::get_nodes())
}

/// Pending response message. Release the result with `free_status`.
#[no_mangle]
pub extern "C" fn get_response_msg() -> *mut c_char {
    into_c_string(leaf::get_response_msg())
}

#[no_mangle]
pub extern "C" fn push_client_msg(s: *const c_char) {
    if let Some(m) = from_c_str(s) { leaf::push_client_msg(m); }
}

#[no_mangle]
pub extern "C" fn push_transaction_msg(s: *const c_char) {
    if let Some(m) = from_c_str(s) { leaf::push_transaction_msg(m); }
}

#[no_mangle]
pub extern "C" fn push_sell_msg(s: *const c_char) {
    if let Some(m) = from_c_str(s) { leaf::push_sell_msg(m); }
}

#[no_mangle]
pub extern "C" fn push_order_msg(s: *const c_char) {
    if let Some(m) = from_c_str(s) { leaf::push_order_msg(m); }
}

// ---------------------------------------------------------------------------
// P2P connector (Go, libp2pconnector.a), iOS only.
//
// Android loads libp2pconnector.so at runtime through libloading; iOS cannot
// dlopen a bundled library from an extension, so the Go archive is linked
// statically into the final binary that also links libleaf.a.  The extern
// symbols below are resolved at that final link.
// ---------------------------------------------------------------------------
#[cfg(any(target_os = "ios", target_os = "macos"))]
mod connector {
    use super::{from_c_str, into_c_string};
    use std::os::raw::{c_char, c_int};
    use std::sync::Mutex;

    extern "C" {
        fn P2PConnectorStart(config_json: *mut c_char) -> c_int;
        fn P2PConnectorStop() -> c_int;
        fn P2PConnectorStatus() -> *mut c_char;
        fn P2PConnectorFree(ptr: *mut c_char);
    }

    // Set when the last start request was a non-transparent (plain Shadowsocks) config.
    static DISABLED: Mutex<bool> = Mutex::new(false);

    /// Same rule as the Android glue: only "transparent" / "auto" start the connector.
    fn transparent_mode(config_json: &str) -> bool {
        let Some(pos) = config_json.find("\"proxy_mode\"") else { return false };
        let Some(colon) = config_json[pos..].find(':') else { return false };
        let rest = config_json[pos + colon + 1..].trim_start();
        let Some(rest) = rest.strip_prefix('"') else { return false };
        let Some(end) = rest.find('"') else { return false };
        let mode = rest[..end].trim();
        mode.eq_ignore_ascii_case("transparent") || mode.eq_ignore_ascii_case("auto")
    }

    /// Starts the connector. Returns 0 on success (also 0 when skipped for a
    /// non-transparent config), -101 for a bad argument, otherwise the Go result.
    #[no_mangle]
    pub extern "C" fn leaf_connector_start(config_json: *const c_char) -> i32 {
        let Some(cfg) = from_c_str(config_json) else { return -101 };
        if !transparent_mode(&cfg) {
            *DISABLED.lock().unwrap_or_else(|e| e.into_inner()) = true;
            return 0;
        }
        *DISABLED.lock().unwrap_or_else(|e| e.into_inner()) = false;
        let Ok(c) = std::ffi::CString::new(cfg) else { return -101 };
        unsafe { P2PConnectorStart(c.as_ptr() as *mut c_char) as i32 }
    }

    #[no_mangle]
    pub extern "C" fn leaf_connector_stop() -> i32 {
        *DISABLED.lock().unwrap_or_else(|e| e.into_inner()) = false;
        unsafe { P2PConnectorStop() as i32 }
    }

    /// Connector status JSON. Release the result with `free_status`.
    #[no_mangle]
    pub extern "C" fn leaf_connector_status() -> *mut c_char {
        if *DISABLED.lock().unwrap_or_else(|e| e.into_inner()) {
            return into_c_string(
                "{\"running\":false,\"enabled\":false,\"proxy_mode\":\"shadowsocks\"}".to_string(),
            );
        }
        unsafe {
            let p = P2PConnectorStatus();
            if p.is_null() {
                return into_c_string("{\"running\":false,\"error\":\"nil status\"}".to_string());
            }
            let s = std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned();
            P2PConnectorFree(p);
            into_c_string(s)
        }
    }
}

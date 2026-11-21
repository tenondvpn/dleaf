use jni::{
    objects::{JClass, JString},
    sys, JNIEnv,
};
use libloading::Library;
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Mutex, Once},
};

type ConnectorStart = unsafe extern "C" fn(*const c_char) -> c_int;
type ConnectorStop = unsafe extern "C" fn() -> c_int;
type ConnectorStatus = unsafe extern "C" fn() -> *mut c_char;
type ConnectorFree = unsafe extern "C" fn(*mut c_char);

struct ConnectorLib {
    _lib: Library,
    start: ConnectorStart,
    stop: ConnectorStop,
    status: ConnectorStatus,
    free: ConnectorFree,
}

static CONNECTOR: Mutex<Option<ConnectorLib>> = Mutex::new(None);
static CONNECTOR_DISABLED: Mutex<bool> = Mutex::new(false);
static INIT_LOGGING: Once = Once::new();

fn android_log_info(message: &str) {
    android_log(android_log_sys::LogPriority::INFO as c_int, message);
}

fn android_log_error(message: &str) {
    android_log(android_log_sys::LogPriority::ERROR as c_int, message);
}

fn android_log(priority: c_int, message: &str) {
    let Ok(tag) = CString::new("SethVpn") else {
        return;
    };
    let Ok(format) = CString::new("%s") else {
        return;
    };
    let Ok(message) = CString::new(message) else {
        return;
    };
    unsafe {
        android_log_sys::__android_log_print(
            priority,
            tag.as_ptr(),
            format.as_ptr(),
            message.as_ptr(),
        );
    }
}

fn init_native_logging() {
    INIT_LOGGING.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let thread = std::thread::current();
            let name = thread.name().unwrap_or("<unnamed>");
            let location = info
                .location()
                .map(|loc| format!("{}:{}", loc.file(), loc.line()))
                .unwrap_or_else(|| "<unknown>".to_string());
            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .map(str::to_string)
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            android_log_error(&format!(
                "native panic thread={} at {}: {}",
                name, location, payload
            ));
            android_log_error(&format!(
                "native panic backtrace:\n{:?}",
                std::backtrace::Backtrace::force_capture()
            ));
        }));
    });
}

fn panic_payload_to_string(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .copied()
        .map(str::to_string)
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic payload>".to_string())
}

unsafe fn load_connector(path: Option<String>) -> Result<(), String> {
    init_native_logging();
    let mut guard = CONNECTOR
        .lock()
        .map_err(|_| "connector lock poisoned".to_string())?;
    if guard.is_some() {
        return Ok(());
    }
    let candidates = if let Some(path) = path {
        vec![path]
    } else {
        vec!["libp2pconnector.so".to_string(), "p2pconnector".to_string()]
    };
    let mut last_err = String::new();
    for candidate in candidates {
        match Library::new(&candidate) {
            Ok(lib) => {
                let start: ConnectorStart = *lib
                    .get::<ConnectorStart>(b"P2PConnectorStart")
                    .map_err(|e| e.to_string())?;
                let stop: ConnectorStop = *lib
                    .get::<ConnectorStop>(b"P2PConnectorStop")
                    .map_err(|e| e.to_string())?;
                let status: ConnectorStatus = *lib
                    .get::<ConnectorStatus>(b"P2PConnectorStatus")
                    .map_err(|e| e.to_string())?;
                let free: ConnectorFree = *lib
                    .get::<ConnectorFree>(b"P2PConnectorFree")
                    .map_err(|e| e.to_string())?;
                *guard = Some(ConnectorLib {
                    start,
                    stop,
                    status,
                    free,
                    _lib: lib,
                });
                return Ok(());
            }
            Err(e) => {
                last_err = e.to_string();
                android_log_error(&format!(
                    "load p2p connector failed candidate={} error={}",
                    candidate, last_err
                ));
            }
        }
    }
    Err(last_err)
}

unsafe fn start_connector(config_json: String) -> i32 {
    init_native_logging();
    if !connector_transparent_mode(&config_json) {
        if let Ok(mut disabled) = CONNECTOR_DISABLED.lock() {
            *disabled = true;
        }
        android_log_info("start p2p connector skipped for non-transparent mode");
        return 0;
    }
    if let Ok(mut disabled) = CONNECTOR_DISABLED.lock() {
        *disabled = false;
    }
    if let Err(e) = load_connector(None) {
        eprintln!("load p2p connector failed: {}", e);
        return -100;
    }
    let config = match CString::new(config_json) {
        Ok(config) => config,
        Err(_) => return -101,
    };
    let guard = match CONNECTOR.lock() {
        Ok(guard) => guard,
        Err(_) => return -102,
    };
    match guard.as_ref() {
        Some(connector) => {
            let result = (connector.start)(config.as_ptr()) as i32;
            result
        }
        None => -103,
    }
}

fn connector_transparent_mode(config_json: &str) -> bool {
    let Some(pos) = config_json.find("\"proxy_mode\"") else {
        return false;
    };
    let Some(colon) = config_json[pos..].find(':') else {
        return false;
    };
    let rest = config_json[pos + colon + 1..].trim_start();
    let Some(rest) = rest.strip_prefix('"') else {
        return false;
    };
    let Some(end) = rest.find('"') else {
        return false;
    };
    let mode = rest[..end].trim();
    mode.eq_ignore_ascii_case("transparent") || mode.eq_ignore_ascii_case("auto")
}

unsafe fn stop_connector() -> i32 {
    init_native_logging();
    if let Ok(mut disabled) = CONNECTOR_DISABLED.lock() {
        *disabled = false;
    }
    let guard = match CONNECTOR.lock() {
        Ok(guard) => guard,
        Err(_) => return -102,
    };
    match guard.as_ref() {
        Some(connector) => (connector.stop)() as i32,
        None => 0,
    }
}

unsafe fn connector_status() -> String {
    init_native_logging();
    if CONNECTOR_DISABLED
        .lock()
        .map(|disabled| *disabled)
        .unwrap_or(false)
    {
        return "{\"running\":false,\"enabled\":false,\"proxy_mode\":\"shadowsocks\"}".to_string();
    }
    let guard = match CONNECTOR.lock() {
        Ok(guard) => guard,
        Err(_) => return "{\"running\":false,\"error\":\"connector lock poisoned\"}".to_string(),
    };
    let Some(connector) = guard.as_ref() else {
        return "{\"running\":false}".to_string();
    };
    let ptr = (connector.status)();
    if ptr.is_null() {
        return "{\"running\":false,\"error\":\"nil status\"}".to_string();
    }
    let status = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    (connector.free)(ptr);
    status
}

unsafe fn jstring_to_string(env: JNIEnv, value: JString) -> Result<String, String> {
    env.get_string(value)
        .map_err(|e| format!("read Java string failed: {}", e))?
        .to_str()
        .map_err(|e| format!("Java string is not valid UTF-8: {}", e))
        .map(|s| s.to_owned())
}

unsafe fn run_leaf(env: JNIEnv, config_path: JString) -> i32 {
    init_native_logging();
    // Tokio 1.48 falls back to std::thread::available_parallelism() when a
    // multi-thread runtime does not specify worker count. On Android 17
    // emulators that can probe cgroups and abort under SELinux denial, so pin
    // the process-wide default before leaf or any dependency starts a runtime.
    std::env::set_var("TOKIO_WORKER_THREADS", "1");
    let config_path = match jstring_to_string(env, config_path) {
        Ok(config_path) => config_path,
        Err(e) => {
            android_log_error(&format!("leaf run failed before start: {}", e));
            return -1;
        }
    };
    let opts = leaf::StartOptions {
        config: leaf::Config::File(config_path),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        // Android 17 16 KB page-size images can deny the cgroup probing used
        // while creating Tokio worker threads. Keep the VPN runtime on the
        // current JNI thread so those probes are not needed.
        runtime_opt: leaf::RuntimeOption::SingleThread,
    };
    match leaf::start(0, opts) {
        Ok(()) => {
            android_log_info("leaf start returned ok");
            0
        }
        Err(e) => {
            android_log_error(&format!("leaf start failed: {}", e));
            -2
        }
    }
}

fn stop_leaf() -> sys::jboolean {
    if leaf::shutdown(0) {
        sys::JNI_TRUE
    } else {
        sys::JNI_FALSE
    }
}

/// Re-reads the config file the running leaf was started with and rebuilds its outbounds,
/// routing rules and DNS, leaving the TUN and the listeners alone.  Used to swap the vpn node
/// (its key and address live in the shadowsocks outbound's password) without tearing the
/// tunnel down.  Returns 0 on success, a negative number otherwise (-1: reload failed,
/// -2: no running leaf, -200: native panic).
///
/// Blocks until the reload finished, so it must not be called from the thread that runs leaf.
///
/// What a reload does NOT pick up: the PAC settings (PAC_MODE / LOCAL_COUNTRY are read once at
/// start), the TUN fd and the listeners.  Use it only to change what the config file says about
/// outbounds, routing rules and DNS; the global client public key (`set_pk`) is not in the file
/// and must be set before calling this.
fn reload_leaf() -> i32 {
    if !leaf::is_running(0) {
        return -2;
    }
    match leaf::reload(0) {
        Ok(()) => 0,
        Err(e) => {
            android_log_error(&format!("leaf reload failed: {}", e));
            -1
        }
    }
}

fn is_leaf_running() -> sys::jboolean {
    if leaf::is_running(0) {
        sys::JNI_TRUE
    } else {
        sys::JNI_FALSE
    }
}

fn java_string(env: JNIEnv, value: String) -> sys::jstring {
    env.new_string(value)
        .expect("Couldn't create java string!")
        .into_inner()
}

unsafe fn set_client_pk(env: JNIEnv, pk: JString) {
    if let Ok(pk) = jstring_to_string(env, pk) {
        leaf::set_pk(pk);
    }
}

unsafe fn set_client_pk_hash(env: JNIEnv, pk: JString) {
    if let Ok(pk) = jstring_to_string(env, pk) {
        leaf::set_pk_hash(pk);
    }
}

fn set_p2p_ss(enabled: sys::jboolean) {
    leaf::set_p2p_ss(enabled != sys::JNI_FALSE);
}

fn set_drop_quic(drop: sys::jboolean) {
    leaf::set_drop_quic(drop != sys::JNI_FALSE);
}

unsafe fn push_client_msg(env: JNIEnv, msg: JString) {
    if let Ok(msg) = jstring_to_string(env, msg) {
        leaf::push_client_msg(msg);
    }
}

unsafe fn push_transaction_msg(env: JNIEnv, msg: JString) {
    if let Ok(msg) = jstring_to_string(env, msg) {
        leaf::push_transaction_msg(msg);
    }
}

unsafe fn push_sell_msg(env: JNIEnv, msg: JString) {
    if let Ok(msg) = jstring_to_string(env, msg) {
        leaf::push_sell_msg(msg);
    }
}

unsafe fn push_order_msg(env: JNIEnv, msg: JString) {
    if let Ok(msg) = jstring_to_string(env, msg) {
        leaf::push_order_msg(msg);
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_runLeaf(
    env: JNIEnv,
    _: JClass,
    config_path: JString,
) -> sys::jint {
    init_native_logging();
    match catch_unwind(AssertUnwindSafe(|| run_leaf(env, config_path))) {
        Ok(result) => result as sys::jint,
        Err(payload) => {
            android_log_error(&format!(
                "runLeaf caught native panic: {}",
                panic_payload_to_string(payload.as_ref())
            ));
            -200
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_stopLeaf(
    _: JNIEnv,
    _: JClass,
) -> sys::jboolean {
    stop_leaf()
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_clearNode(
    env: JNIEnv,
    _: JClass,
    ip: JString,
) -> sys::jboolean {
    let ip = match jstring_to_string(env, ip) {
        Ok(ip) => ip,
        Err(e) => {
            android_log_error(&format!("clearNode: {}", e));
            return sys::JNI_FALSE;
        }
    };
    match catch_unwind(AssertUnwindSafe(|| leaf::clear_node(&ip))) {
        Ok(true) => sys::JNI_TRUE,
        Ok(false) => sys::JNI_FALSE,
        Err(payload) => {
            android_log_error(&format!(
                "clearNode caught native panic: {}",
                panic_payload_to_string(payload.as_ref())
            ));
            sys::JNI_FALSE
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_clearNode(
    env: JNIEnv,
    class: JClass,
    ip: JString,
) -> sys::jboolean {
    Java_com_leaf_example_aleaf_SimpleVpnService_clearNode(env, class, ip)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_reloadLeaf(
    _: JNIEnv,
    _: JClass,
) -> sys::jint {
    match catch_unwind(AssertUnwindSafe(reload_leaf)) {
        Ok(result) => result as sys::jint,
        Err(payload) => {
            android_log_error(&format!(
                "reloadLeaf caught native panic: {}",
                panic_payload_to_string(payload.as_ref())
            ));
            -200
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_isLeafRunning(
    _: JNIEnv,
    _: JClass,
) -> sys::jboolean {
    is_leaf_running()
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_getStatus(
    env: JNIEnv,
    _: JClass,
) -> sys::jstring {
    java_string(env, leaf::get_status())
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_getNodes(
    env: JNIEnv,
    _: JClass,
) -> sys::jstring {
    java_string(env, leaf::get_nodes())
}

// Route decisions of the running leaf for "host:port,host:port,..." (no connection is made).
// Returns JSON, see leaf::route_probe.
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_routeProbe(
    env: JNIEnv,
    _: JClass,
    targets: JString,
) -> sys::jstring {
    let json = match catch_unwind(AssertUnwindSafe(|| {
        let raw = jstring_to_string(env, targets).unwrap_or_default();
        let parsed: Vec<(String, u16)> = raw
            .split(',')
            .filter_map(|item| {
                let item = item.trim();
                let (host, port) = item.rsplit_once(':')?;
                let port = port.parse::<u16>().ok()?;
                if host.is_empty() {
                    None
                } else {
                    Some((host.to_string(), port))
                }
            })
            .collect();
        leaf::route_probe(&parsed)
    })) {
        Ok(s) => s,
        Err(_) => r#"{"running":false,"results":[],"error":"panic"}"#.to_string(),
    };
    java_string(env, json)
}

// Cumulative "down,up" bytes through leaf's outbounds (monotonic; the caller differences two
// samples for a rate).  "0,0" until ENABLE_STATS is on and traffic flows.
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_trafficBytes(
    env: JNIEnv,
    _: JClass,
) -> sys::jstring {
    let (down, up) = leaf::traffic_bytes();
    java_string(env, format!("{},{}", down, up))
}

// Per-server DNS results of the running leaf for one host (see leaf::dns_probe).
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_dnsProbe(
    env: JNIEnv,
    _: JClass,
    host: JString,
) -> sys::jstring {
    let json = match catch_unwind(AssertUnwindSafe(|| {
        let host = jstring_to_string(env, host).unwrap_or_default();
        leaf::dns_probe(host.trim())
    })) {
        Ok(s) => s,
        Err(_) => r#"{"running":false,"host":"","servers":[],"error":"panic"}"#.to_string(),
    };
    java_string(env, json)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_startP2PConnector(
    env: JNIEnv,
    _: JClass,
    config_json: JString,
) -> sys::jint {
    init_native_logging();
    match catch_unwind(AssertUnwindSafe(|| {
        match jstring_to_string(env, config_json) {
            Ok(config_json) => start_connector(config_json) as sys::jint,
            Err(e) => {
                android_log_error(&format!("p2p connector start failed before load: {}", e));
                -101
            }
        }
    })) {
        Ok(result) => result,
        Err(payload) => {
            android_log_error(&format!(
                "startP2PConnector caught native panic: {}",
                panic_payload_to_string(payload.as_ref())
            ));
            -201
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_stopP2PConnector(
    _: JNIEnv,
    _: JClass,
) -> sys::jint {
    stop_connector() as sys::jint
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_getP2PConnectorStatus(
    env: JNIEnv,
    _: JClass,
) -> sys::jstring {
    java_string(env, connector_status())
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_setClientPk(
    env: JNIEnv,
    _: JClass,
    pk: JString,
) {
    set_client_pk(env, pk);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_setClientPkHash(
    env: JNIEnv,
    _: JClass,
    pk: JString,
) {
    set_client_pk_hash(env, pk);
}

// Whether the TUN inbound drops app UDP 443 (QUIC) so apps fall back to TCP.  `true` = drop,
// `false` = forward.  Takes effect at once and may be called before or after runLeaf.
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_setDropQuic(
    _env: JNIEnv,
    _: JClass,
    drop: sys::jboolean,
) {
    set_drop_quic(drop);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_setP2pSs(
    _env: JNIEnv,
    _: JClass,
    enabled: sys::jboolean,
) {
    set_p2p_ss(enabled);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_client_pushClientMsg(
    env: JNIEnv,
    _: JClass,
    msg: JString,
) {
    push_client_msg(env, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_client_getResponseMsg(
    env: JNIEnv,
    _: JClass,
) -> sys::jstring {
    java_string(env, leaf::get_response_msg())
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_client_pushTransactionMsg(
    env: JNIEnv,
    _: JClass,
    msg: JString,
) {
    push_transaction_msg(env, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_client_pushSellMsg(
    env: JNIEnv,
    _: JClass,
    msg: JString,
) {
    push_sell_msg(env, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_client_pushOrderMsg(
    env: JNIEnv,
    _: JClass,
    msg: JString,
) {
    push_order_msg(env, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_runLeaf(
    env: JNIEnv,
    class: JClass,
    config_path: JString,
) -> sys::jint {
    Java_com_leaf_example_aleaf_SimpleVpnService_runLeaf(env, class, config_path)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_stopLeaf(
    env: JNIEnv,
    class: JClass,
) -> sys::jboolean {
    Java_com_leaf_example_aleaf_SimpleVpnService_stopLeaf(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_reloadLeaf(
    env: JNIEnv,
    class: JClass,
) -> sys::jint {
    Java_com_leaf_example_aleaf_SimpleVpnService_reloadLeaf(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_isLeafRunning(
    env: JNIEnv,
    class: JClass,
) -> sys::jboolean {
    Java_com_leaf_example_aleaf_SimpleVpnService_isLeafRunning(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_getStatus(
    env: JNIEnv,
    class: JClass,
) -> sys::jstring {
    Java_com_leaf_example_aleaf_SimpleVpnService_getStatus(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_getNodes(
    env: JNIEnv,
    class: JClass,
) -> sys::jstring {
    Java_com_leaf_example_aleaf_SimpleVpnService_getNodes(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_startP2PConnector(
    env: JNIEnv,
    class: JClass,
    config_json: JString,
) -> sys::jint {
    Java_com_leaf_example_aleaf_SimpleVpnService_startP2PConnector(env, class, config_json)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_stopP2PConnector(
    env: JNIEnv,
    class: JClass,
) -> sys::jint {
    Java_com_leaf_example_aleaf_SimpleVpnService_stopP2PConnector(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_getP2PConnectorStatus(
    env: JNIEnv,
    class: JClass,
) -> sys::jstring {
    Java_com_leaf_example_aleaf_SimpleVpnService_getP2PConnectorStatus(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_setClientPk(
    env: JNIEnv,
    class: JClass,
    pk: JString,
) {
    Java_com_leaf_example_aleaf_SimpleVpnService_setClientPk(env, class, pk);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_setClientPkHash(
    env: JNIEnv,
    class: JClass,
    pk: JString,
) {
    Java_com_leaf_example_aleaf_SimpleVpnService_setClientPkHash(env, class, pk);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_SimpleVpnService_setP2pSs(
    env: JNIEnv,
    class: JClass,
    enabled: sys::jboolean,
) {
    Java_com_leaf_example_aleaf_SimpleVpnService_setP2pSs(env, class, enabled);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_client_pushClientMsg(
    env: JNIEnv,
    class: JClass,
    msg: JString,
) {
    Java_com_leaf_example_aleaf_client_pushClientMsg(env, class, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_client_getResponseMsg(
    env: JNIEnv,
    class: JClass,
) -> sys::jstring {
    Java_com_leaf_example_aleaf_client_getResponseMsg(env, class)
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_client_pushTransactionMsg(
    env: JNIEnv,
    class: JClass,
    msg: JString,
) {
    Java_com_leaf_example_aleaf_client_pushTransactionMsg(env, class, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_client_pushSellMsg(
    env: JNIEnv,
    class: JClass,
    msg: JString,
) {
    Java_com_leaf_example_aleaf_client_pushSellMsg(env, class, msg);
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_leaf_example_aleaf_client_pushOrderMsg(
    env: JNIEnv,
    class: JClass,
    msg: JString,
) {
    Java_com_leaf_example_aleaf_client_pushOrderMsg(env, class, msg);
}

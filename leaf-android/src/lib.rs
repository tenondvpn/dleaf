use jni::{
    objects::{JClass, JString},
    sys, JNIEnv,
};
use libloading::Library;
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    sync::Mutex,
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

unsafe fn load_connector(path: Option<String>) -> Result<(), String> {
    let mut guard = CONNECTOR.lock().map_err(|_| "connector lock poisoned".to_string())?;
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
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}

unsafe fn start_connector(config_json: String) -> i32 {
    if !connector_transparent_mode(&config_json) {
        if let Ok(mut disabled) = CONNECTOR_DISABLED.lock() {
            *disabled = true;
        }
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
        Some(connector) => (connector.start)(config.as_ptr()) as i32,
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
    if CONNECTOR_DISABLED.lock().map(|disabled| *disabled).unwrap_or(false) {
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

unsafe fn jstring_to_string(env: JNIEnv, value: JString) -> String {
    env.get_string(value)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

unsafe fn run_leaf(env: JNIEnv, config_path: JString) {
    let config_path = jstring_to_string(env, config_path);
    let opts = leaf::StartOptions {
        config: leaf::Config::File(config_path),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: leaf::RuntimeOption::MultiThreadAuto(1024 * 1024),
    };
    leaf::start(0, opts).unwrap();
}

fn stop_leaf() -> sys::jboolean {
    if leaf::shutdown(0) {
        sys::JNI_TRUE
    } else {
        sys::JNI_FALSE
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
    leaf::set_pk(jstring_to_string(env, pk));
}

unsafe fn set_client_pk_hash(env: JNIEnv, pk: JString) {
    leaf::set_pk_hash(jstring_to_string(env, pk));
}

unsafe fn push_client_msg(env: JNIEnv, msg: JString) {
    leaf::push_client_msg(jstring_to_string(env, msg));
}

unsafe fn push_transaction_msg(env: JNIEnv, msg: JString) {
    leaf::push_transaction_msg(jstring_to_string(env, msg));
}

unsafe fn push_sell_msg(env: JNIEnv, msg: JString) {
    leaf::push_sell_msg(jstring_to_string(env, msg));
}

unsafe fn push_order_msg(env: JNIEnv, msg: JString) {
    leaf::push_order_msg(jstring_to_string(env, msg));
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_runLeaf(
    env: JNIEnv,
    _: JClass,
    config_path: JString,
) {
    run_leaf(env, config_path);
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

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_leaf_example_aleaf_SimpleVpnService_startP2PConnector(
    env: JNIEnv,
    _: JClass,
    config_json: JString,
) -> sys::jint {
    start_connector(jstring_to_string(env, config_json)) as sys::jint
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
) {
    Java_com_leaf_example_aleaf_SimpleVpnService_runLeaf(env, class, config_path);
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

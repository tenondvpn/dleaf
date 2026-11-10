use chrono::DateTime;
use chrono::Local;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::panic;
use std::process;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use xxhash_rust::const_xxh3::xxh3_64 as const_xxh3;
use xxhash_rust::xxh3::xxh3_64;
use xxhash_rust::xxh32;

lazy_static! {
    static ref valid_routes: Mutex<String> = Mutex::new(String::from(""));
    static ref vpn_nodes: Mutex<String> = Mutex::new(String::from(""));
    static ref client_pk: Mutex<String> = Mutex::new(String::from(""));
    static ref client_pk_hash: Mutex<String> = Mutex::new(String::from(""));
    static ref started: Mutex<u32> = Mutex::new(0);
    static ref connection_map: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    static ref connection_status: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
    static ref tx_list_msg: Mutex<String> = Mutex::new(String::from(""));
    static ref transaction_msg: Mutex<String> = Mutex::new(String::from(""));
    static ref sell_msg: Mutex<String> = Mutex::new(String::from(""));
    static ref order_msg: Mutex<String> = Mutex::new(String::from(""));
    static ref res_queue: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
}

// p2p-ss mode flag. When true, the shadowsocks outbound MUST encrypt (ShadowedStream)
// regardless of the via_connector suffix — p2p-ss relays ENCRYPTED traffic through a
// route node to the vpn node's ss port. Set from the Android layer via set_p2p_ss().
static P2P_SS: AtomicBool = AtomicBool::new(false);

pub fn SetP2pSs(enabled: bool) {
    P2P_SS.store(enabled, Ordering::Relaxed);
}

pub fn GetP2pSs() -> bool {
    P2P_SS.load(Ordering::Relaxed)
}

pub fn GetValidRoutes() -> String {
    let res = valid_routes.lock().unwrap().clone();
    valid_routes.lock().unwrap().clear();
    res
}

pub fn SetValidRoutes(data: String) {
    let mut v = valid_routes.lock().unwrap();
    v.push_str(&data);
    v.push_str(",");
}

pub fn SetVpnNodes(data: String) {
    vpn_nodes.lock().unwrap().clear();
    let mut v = vpn_nodes.lock().unwrap();
    v.push_str(&data);
}

pub fn GetVpnNodes() -> String {
    let mut v = vpn_nodes.lock().unwrap().clone();
    vpn_nodes.lock().unwrap().clear();
    v
}

pub fn SetResponseHash(svr_add: String, val: String) {
    let mut v = connection_map.lock().unwrap();
    v.insert(svr_add, val);
}

pub fn GetResponseHash(svr_add: String) -> String {
    let mut v = connection_map.lock().unwrap();
    let tmp = "".to_string();
    let val = v.get(&svr_add).unwrap_or(&tmp);
    let tmp_val = val.to_string();
    let vec: Vec<&str> = tmp_val.split(",").collect();
    if (vec.len() >= 2) {
        vec[0].to_string()
    } else {
        val.to_string()
    }
}

pub fn SetResponseStatus(svr_add: String, val: bool) {
    let mut v = connection_status.lock().unwrap();
    v.insert(svr_add, val);
}

pub fn GetResponseStatus(svr_add: String) -> bool {
    let mut v = connection_status.lock().unwrap();
    let tmp: bool = false;
    let val = v.get(&svr_add).unwrap_or(&tmp);
    *val
}

pub fn ClearAll() {
    valid_routes.lock().unwrap().clear();
    connection_map.lock().unwrap().clear();
    connection_status.lock().unwrap().clear();
}

// Fixed server ports (no per-day (ip+timestamp) hash). The two callers pass the
// vpn-server range [10000,35000) or the route range [35000,65000); we map the
// route range (min_port >= 35000) to 18764 and the vpn-server range to 28764.
// The same two values are hardcoded on the server (C++ GetVpnServerPort /
// GetVpnRoutePort) and the clients, so all sides agree without recomputation.
pub const FIXED_VPN_SERVER_PORT: u16 = 28764;
pub const FIXED_VPN_ROUTE_PORT: u16 = 18764;
pub fn get_port_with_ip(_ip: String, min_port: u32, _max_port: u32) -> u16 {
    if min_port >= 35000 {
        FIXED_VPN_ROUTE_PORT
    } else {
        FIXED_VPN_SERVER_PORT
    }
}

pub fn PushClientMsg(msg: String) {
    tx_list_msg.lock().unwrap().clear();
    let mut v = tx_list_msg.lock().unwrap();
    v.push_str(&msg);
}

pub fn GetClientMsg() -> String {
    let mut v = tx_list_msg.lock().unwrap().clone();
    tx_list_msg.lock().unwrap().clear();
    v
}

pub fn PushTransactionMsg(msg: String) {
    transaction_msg.lock().unwrap().clear();
    let mut v = transaction_msg.lock().unwrap();
    v.push_str(&msg);
}

pub fn GetTransactionMsg() -> String {
    let mut v = transaction_msg.lock().unwrap().clone();
    transaction_msg.lock().unwrap().clear();
    v
}

pub fn PushSellMsg(msg: String) {
    sell_msg.lock().unwrap().clear();
    let mut v = sell_msg.lock().unwrap();
    v.push_str(&msg);
}

pub fn GetSellMsg() -> String {
    let mut v = sell_msg.lock().unwrap().clone();
    sell_msg.lock().unwrap().clear();
    v
}

pub fn PushOrderMsg(msg: String) {
    order_msg.lock().unwrap().clear();
    let mut v = order_msg.lock().unwrap();
    v.push_str(&msg);
}

pub fn GetOrderMsg() -> String {
    let mut v = order_msg.lock().unwrap().clone();
    order_msg.lock().unwrap().clear();
    v
}

pub fn PushResponseMsg(msg: String) {
    let mut v = res_queue.lock().unwrap();
    v.push_back(msg);
}

pub fn GetResponseMsg() -> String {
    let mut v = res_queue.lock().unwrap();
    if (v.is_empty()) {
        "".to_string()
    } else {
        let msg = v.front().unwrap().clone();
        v.pop_front();
        (*msg).to_string()
    }
}

pub fn SetClientPk(pk: String) {
    client_pk.lock().unwrap().clear();
    let mut v = client_pk.lock().unwrap();
    v.push_str(&pk);
}

pub fn GetClientPk() -> String {
    let mut v = client_pk.lock().unwrap().clone();
    v
}

pub fn SetClientPkHash(pk: String) {
    client_pk_hash.lock().unwrap().clear();
    let mut v = client_pk_hash.lock().unwrap();
    v.push_str(&pk);
}

pub fn GetClientPkHash() -> String {
    let mut msg = GetTransactionMsg();
    if (msg.is_empty()) {
        msg = GetClientMsg();
    }

    if (msg.is_empty()) {
        msg = GetSellMsg();
    }

    if (msg.is_empty()) {
        msg = GetOrderMsg();
    }

    if (!msg.is_empty()) {
        msg
    } else {
        let mut v = client_pk_hash.lock().unwrap().clone();
        v
    }
}

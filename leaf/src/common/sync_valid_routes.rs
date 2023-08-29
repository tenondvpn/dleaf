use std::thread;
use std::time::Duration;
use std::process;
use std::panic;
//extern crate easy_http_request;
use std::collections::HashMap;
use chrono::DateTime;
use chrono::Local;
use xxhash_rust::const_xxh3::xxh3_64 as const_xxh3;
use xxhash_rust::xxh3::xxh3_64;
use xxhash_rust::xxh32;
//use easy_http_request::DefaultHttpRequest;
use std::sync::Mutex;
use lazy_static::lazy_static;
lazy_static! {
    static ref valid_routes: Mutex<String> = Mutex::new(String::from(""));
    static ref valid_tmp_id: Mutex<String> = Mutex::new(String::from(""));
    static ref vpn_nodes: Mutex<String> = Mutex::new(String::from(""));
    static ref client_pk: Mutex<String> = Mutex::new(String::from(""));
    static ref client_pk_hash: Mutex<String> = Mutex::new(String::from(""));
    static ref started: Mutex<u32> = Mutex::new(0);
    static ref connection_map: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    static ref connection_status: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
}

pub fn StartThread(id: String) {
    let mut v = started.lock().unwrap();
    if (*v > 0) {
        return;
    }

    *v = 1;
    {
        let mut tmp_v = valid_tmp_id.lock().unwrap();
        tmp_v.push_str(&id.clone());
    }
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
    let vec :Vec<&str> = tmp_val.split(",").collect();
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
    let tmp : bool = false;
    let val = v.get(&svr_add).unwrap_or(&tmp);
    *val
}

pub fn ClearAll() {
    valid_routes.lock().unwrap().clear();
    connection_map.lock().unwrap().clear();
    connection_status.lock().unwrap().clear();
}

pub fn get_port_with_ip(ip: String, min_port: u32, max_port: u32) ->u16 {
    let dt: DateTime<Local> = Local::now();
    let timestamp = dt.timestamp() / (3600 * 24);
    let mut tmp_str = ip.clone();
    tmp_str += &timestamp.to_string();
    let port_hash = xxh32::xxh32(tmp_str.as_bytes(), 623453345u32);
    let port = ((port_hash % (max_port - min_port)) + min_port);
    return port as u16;
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
    let mut v = client_pk_hash.lock().unwrap().clone();
    v
}
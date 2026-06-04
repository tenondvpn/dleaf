// Windows network operations using Win32 API only — no child processes.
use std::net::{Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, CreateIpForwardEntry2, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetAdaptersAddresses,
    GetIpForwardTable2, InitializeIpForwardEntry, InitializeUnicastIpAddressEntry,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_UNICASTIPADDRESS_ROW,
    GAA_FLAG_INCLUDE_PREFIX,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKET_ADDRESS,
};

// Helper: u32 in host order → BE bytes for IN_ADDR
fn ipv4_to_in_addr(ip: Ipv4Addr) -> IN_ADDR {
    let octets = ip.octets();
    let mut s_un = [0u8; 4];
    s_un.copy_from_slice(&octets);
    IN_ADDR { S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 { S_addr: u32::from_be_bytes(octets) } }
}

fn in_addr_to_ipv4(addr: &IN_ADDR) -> Ipv4Addr {
    Ipv4Addr::from(unsafe { addr.S_un.S_addr }.to_be_bytes())
}

// ─── Route table helpers ────────────────────────────────────────────────────

fn get_forward_table() -> Result<*mut MIB_IPFORWARD_TABLE2> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let ret = unsafe { GetIpForwardTable2(AF_INET as u16, &mut table) };
    if ret != NO_ERROR || table.is_null() {
        return Err(anyhow!("GetIpForwardTable2 failed: {}", ret));
    }
    Ok(table)
}

fn add_route(
    dest: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    if_index: u32,
    metric: u32,
) -> Result<()> {
    unsafe {
        let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        InitializeIpForwardEntry(&mut row);
        row.InterfaceIndex = if_index;
        row.DestinationPrefix.PrefixLength = prefix_len;
        row.DestinationPrefix.Prefix.si_family = AF_INET as u16;
        row.DestinationPrefix.Prefix.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: ipv4_to_in_addr(dest),
            sin_zero: [0; 8],
        };
        row.NextHop.si_family = AF_INET as u16;
        row.NextHop.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: ipv4_to_in_addr(gateway),
            sin_zero: [0; 8],
        };
        row.Metric = metric;
        row.Protocol = 3; // MIB_IPPROTO_NETMGMT
        let ret = CreateIpForwardEntry2(&row);
        if ret != NO_ERROR && ret != 0x80070050 {
            // ignore ERROR_OBJECT_ALREADY_EXISTS
            return Err(anyhow!("CreateIpForwardEntry2 failed: {}", ret));
        }
    }
    Ok(())
}

fn delete_routes_on_if(dest: Ipv4Addr, prefix_len: u8, if_index: u32) {
    let table = match get_forward_table() {
        Ok(t) => t,
        Err(_) => return,
    };
    let count = unsafe { (*table).NumEntries as usize };
    let rows: Vec<MIB_IPFORWARD_ROW2> = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), count).to_vec()
    };
    unsafe { FreeMibTable(table as *mut _) };
    let dest_be = u32::from_be_bytes(dest.octets());
    for row in &rows {
        if row.InterfaceIndex != if_index { continue; }
        if row.DestinationPrefix.PrefixLength != prefix_len { continue; }
        if unsafe { row.DestinationPrefix.Prefix.si_family } != AF_INET as u16 { continue; }
        let d = unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr };
        if d != dest_be { continue; }
        unsafe { DeleteIpForwardEntry2(row) };
    }
}

fn delete_routes_all_if(dest: Ipv4Addr, prefix_len: u8) {
    let table = match get_forward_table() {
        Ok(t) => t,
        Err(_) => return,
    };
    let count = unsafe { (*table).NumEntries as usize };
    let rows: Vec<MIB_IPFORWARD_ROW2> = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), count).to_vec()
    };
    unsafe { FreeMibTable(table as *mut _) };
    let dest_be = u32::from_be_bytes(dest.octets());
    for row in &rows {
        if row.DestinationPrefix.PrefixLength != prefix_len { continue; }
        if unsafe { row.DestinationPrefix.Prefix.si_family } != AF_INET as u16 { continue; }
        let d = unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr };
        if d != dest_be { continue; }
        unsafe { DeleteIpForwardEntry2(row) };
    }
}

// ─── Adapter helpers ────────────────────────────────────────────────────────

const WORKING_BUFFER_SIZE: u32 = 15000;

fn find_default_ipv4_route_info() -> Result<(u32 /* if_index */, Ipv4Addr /* gw */)> {
    let table = get_forward_table()?;
    let count = unsafe { (*table).NumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let mut best: Option<(u32, Ipv4Addr, u32)> = None;
    for row in rows {
        if row.DestinationPrefix.PrefixLength != 0 { continue; }
        if unsafe { row.DestinationPrefix.Prefix.si_family } != AF_INET as u16 { continue; }
        let dest = unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr };
        if dest != 0 { continue; }
        if unsafe { row.NextHop.si_family } != AF_INET as u16 { continue; }
        let gw_be = unsafe { row.NextHop.Ipv4.sin_addr.S_un.S_addr };
        if gw_be == 0 { continue; }
        let metric = row.Metric;
        if best.is_none() || metric < best.unwrap().2 {
            best = Some((row.InterfaceIndex, Ipv4Addr::from(gw_be.to_be_bytes()), metric));
        }
    }
    unsafe { FreeMibTable(table as *mut _) };
    best.map(|(idx, gw, _)| (idx, gw))
        .ok_or_else(|| anyhow!("no default IPv4 route found"))
}

fn find_adapter_by_index(if_index: u32) -> Result<(String /* friendly name */, Option<Ipv4Addr>)> {
    let mut buf_len: u32 = WORKING_BUFFER_SIZE;
    let mut buf = vec![0u8; buf_len as usize];
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut _,
            &mut buf_len,
        )
    };
    if ret != NO_ERROR { return Err(anyhow!("GetAdaptersAddresses failed: {}", ret)); }

    let mut ptr = buf.as_ptr() as *const windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;
    while !ptr.is_null() {
        let a = unsafe { &*ptr };
        if unsafe { a.Anonymous1.Anonymous.IfIndex } == if_index {
            let name = adapter_friendly_name(a);
            let ipv4 = adapter_first_ipv4(a);
            return Ok((name, ipv4));
        }
        ptr = unsafe { (*ptr).Next };
    }
    Err(anyhow!("adapter with index {} not found", if_index))
}

fn adapter_friendly_name(a: &windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH) -> String {
    let ptr = a.FriendlyName;
    if ptr.is_null() { return String::new(); }
    let len = (0usize..).take_while(|&i| unsafe { *ptr.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}

fn adapter_first_ipv4(a: &windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH) -> Option<Ipv4Addr> {
    let mut ua = a.FirstUnicastAddress;
    while !ua.is_null() {
        let sa = unsafe { (*ua).Address.lpSockaddr };
        if !sa.is_null() {
            let family = unsafe { (*sa).sa_family };
            if family == AF_INET as u16 {
                let sin = sa as *const SOCKADDR_IN;
                let be = unsafe { (*sin).sin_addr.S_un.S_addr };
                let ip = Ipv4Addr::from(be.to_be_bytes());
                if !ip.to_string().starts_with("169.254.") {
                    return Some(ip);
                }
            }
        }
        ua = unsafe { (*ua).Next };
    }
    None
}

fn find_tun_interface_index() -> Option<u32> {
    // Check env var first (set by leaf runtime)
    if let Ok(s) = std::env::var("LEAF_TUN_INTERFACE_INDEX") {
        if let Ok(idx) = s.trim().parse::<u32>() {
            return Some(idx);
        }
    }
    let target_ip = u32::from_be_bytes(Ipv4Addr::new(10, 255, 0, 2).octets());
    let mut buf_len: u32 = WORKING_BUFFER_SIZE;
    let mut buf = vec![0u8; buf_len as usize];
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut _,
            &mut buf_len,
        )
    };
    if ret != NO_ERROR { return None; }
    let mut ptr = buf.as_ptr() as *const windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;
    while !ptr.is_null() {
        let a = unsafe { &*ptr };
        let name = adapter_friendly_name(a);
        if name.contains("FlutersTun") || name.contains("Wintun") {
            return Some(unsafe { a.Anonymous1.Anonymous.IfIndex });
        }
        // Check for 10.255.0.2
        let mut ua = a.FirstUnicastAddress;
        while !ua.is_null() {
            let sa = unsafe { (*ua).Address.lpSockaddr };
            if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET as u16 {
                let sin = sa as *const SOCKADDR_IN;
                if unsafe { (*sin).sin_addr.S_un.S_addr } == target_ip {
                    return Some(unsafe { a.Anonymous1.Anonymous.IfIndex });
                }
            }
            ua = unsafe { (*ua).Next };
        }
        ptr = unsafe { (*ptr).Next };
    }
    None
}

fn find_adapter_index_by_name(name: &str) -> Result<u32> {
    let mut buf_len: u32 = WORKING_BUFFER_SIZE;
    let mut buf = vec![0u8; buf_len as usize];
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut _,
            &mut buf_len,
        )
    };
    if ret != NO_ERROR { return Err(anyhow!("GetAdaptersAddresses failed: {}", ret)); }
    let mut ptr = buf.as_ptr() as *const windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;
    while !ptr.is_null() {
        let a = unsafe { &*ptr };
        if adapter_friendly_name(a) == name {
            return Ok(unsafe { a.Anonymous1.Anonymous.IfIndex });
        }
        ptr = unsafe { (*ptr).Next };
    }
    Err(anyhow!("adapter '{}' not found", name))
}

// ─── Public API ─────────────────────────────────────────────────────────────

pub fn get_interface_index(name: &str) -> Result<u32> {
    let name = name.trim().strip_prefix("ifindex:").unwrap_or(name.trim());
    if let Ok(idx) = name.parse::<u32>() {
        return Ok(idx);
    }
    if name == "FlutersTun" {
        if let Some(idx) = find_tun_interface_index() {
            return Ok(idx);
        }
    }
    find_adapter_index_by_name(name)
}

pub fn windows_tun_diagnostics() -> Result<String> {
    Ok(format!("TUN if_index={:?}", find_tun_interface_index()))
}

pub fn get_default_ipv4_gateway() -> Result<String> {
    let (_, gw) = find_default_ipv4_route_info()?;
    Ok(gw.to_string())
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    Err(anyhow!("IPv6 gateway lookup not implemented"))
}

pub fn get_default_interface() -> Result<String> {
    let (idx, _) = find_default_ipv4_route_info()?;
    let (name, _) = find_adapter_by_index(idx)?;
    Ok(name)
}

pub fn get_default_interface_index() -> Result<u32> {
    let (idx, _) = find_default_ipv4_route_info()?;
    Ok(idx)
}

pub fn get_default_ipv4_address() -> Result<String> {
    let (idx, _) = find_default_ipv4_route_info()?;
    let (_, ip) = find_adapter_by_index(idx)?;
    ip.map(|a| a.to_string())
        .ok_or_else(|| anyhow!("no IPv4 address on default interface"))
}

pub fn get_default_ipv6_address() -> Result<String> {
    Err(anyhow!("IPv6 address lookup not implemented"))
}

pub fn add_interface_ipv4_address(
    name: &str,
    addr: Ipv4Addr,
    gw: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<()> {
    let if_index = get_interface_index(name)?;
    // Calculate prefix length from mask
    let mask_bits = u32::from(mask);
    let prefix_len = mask_bits.count_ones() as u8;

    // Remove existing address 10.255.0.2 on this interface first
    remove_unicast_address(if_index, addr);

    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = if_index;
        row.Address.si_family = AF_INET as u16;
        row.Address.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: ipv4_to_in_addr(addr),
            sin_zero: [0; 8],
        };
        row.OnLinkPrefixLength = prefix_len;
        let ret = CreateUnicastIpAddressEntry(&row);
        if ret != NO_ERROR && ret != 0x80070050 {
            return Err(anyhow!("CreateUnicastIpAddressEntry failed: {}", ret));
        }
    }
    Ok(())
}

fn remove_unicast_address(if_index: u32, addr: Ipv4Addr) {
    // Try to remove the address if it already exists — ignore errors
    unsafe {
        let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = if_index;
        row.Address.si_family = AF_INET as u16;
        row.Address.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: ipv4_to_in_addr(addr),
            sin_zero: [0; 8],
        };
        DeleteUnicastIpAddressEntry(&row);
    }
}

pub fn add_interface_ipv6_address(_name: &str, _addr: Ipv6Addr, _prefixlen: i32) -> Result<()> {
    // IPv6 not required for current VPN operation
    Ok(())
}

pub fn add_default_ipv4_route(gateway: Ipv4Addr, interface: String, primary: bool) -> Result<()> {
    let metric = if primary { 1u32 } else { 50u32 };
    let idx = get_interface_index(&interface)?;
    delete_routes_on_if(Ipv4Addr::new(0, 0, 0, 0), 0, idx);
    add_route(Ipv4Addr::new(0, 0, 0, 0), 0, gateway, idx, metric)
}

pub fn add_split_ipv4_default_routes(_gateway: Ipv4Addr, interface: String) -> Result<()> {
    let mut idx = None;
    for _ in 0..20 {
        match get_interface_index(&interface) {
            Ok(i) => { idx = Some(i); break; }
            _ => thread::sleep(Duration::from_millis(250)),
        }
    }
    let idx = idx.ok_or_else(|| anyhow!("TUN adapter interface index not found"))?;
    log::info!("Windows TUN route interface index: {}", idx);

    for (dest, plen) in &[
        (Ipv4Addr::new(0, 0, 0, 0), 1u8),
        (Ipv4Addr::new(128, 0, 0, 0), 1u8),
    ] {
        delete_routes_on_if(*dest, *plen, idx);
        add_route(*dest, *plen, Ipv4Addr::new(0, 0, 0, 0), idx, 0)?;
        log::info!("Windows TUN split route added: {}/{} via if {}", dest, plen, idx);
    }
    Ok(())
}

pub fn delete_split_ipv4_default_routes() -> Result<()> {
    delete_routes_all_if(Ipv4Addr::new(0, 0, 0, 0), 1);
    delete_routes_all_if(Ipv4Addr::new(128, 0, 0, 0), 1);
    Ok(())
}

pub fn add_default_ipv6_route(_gateway: Ipv6Addr, _interface: String, _primary: bool) -> Result<()> {
    Ok(())
}

pub fn delete_default_ipv4_route(_ifscope: Option<String>) -> Result<()> {
    delete_routes_all_if(Ipv4Addr::new(0, 0, 0, 0), 0);
    Ok(())
}

pub fn delete_default_ipv6_route(_ifscope: Option<String>) -> Result<()> {
    Ok(())
}

pub fn add_host_ipv4_routes(
    addresses: &[Ipv4Addr],
    gateway: Ipv4Addr,
    interface: Option<String>,
) -> Result<()> {
    if addresses.is_empty() { return Ok(()); }
    let idx = if let Some(ref iface) = interface {
        get_interface_index(iface)?
    } else {
        get_default_interface_index()?
    };
    for &addr in addresses {
        delete_routes_on_if(addr, 32, idx);
        add_route(addr, 32, gateway, idx, 1)?;
    }
    Ok(())
}

pub fn add_host_ipv4_route(
    address: Ipv4Addr,
    gateway: Ipv4Addr,
    interface: Option<String>,
) -> Result<()> {
    add_host_ipv4_routes(&[address], gateway, interface)
}

pub fn delete_host_ipv4_route(address: Ipv4Addr) -> Result<()> {
    delete_routes_all_if(address, 32);
    Ok(())
}

pub fn set_interface_dns(_name: &str, _dns: Ipv4Addr) -> Result<()> {
    // DNS is handled by the TUN stack; skip
    Ok(())
}

pub fn get_ipv4_forwarding() -> Result<bool> { Ok(false) }
pub fn get_ipv6_forwarding() -> Result<bool> { Ok(false) }
pub fn set_ipv4_forwarding(_val: bool) -> Result<()> { Ok(()) }
pub fn set_ipv6_forwarding(_val: bool) -> Result<()> { Ok(()) }

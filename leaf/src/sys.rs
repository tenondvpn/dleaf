use super::common;
use super::option;

pub struct NetInfo {
    pub default_ipv4_gateway: Option<String>,
    pub default_ipv6_gateway: Option<String>,
    pub default_ipv4_address: Option<String>,
    pub default_ipv6_address: Option<String>,
    pub ipv4_forwarding: bool,
    pub ipv6_forwarding: bool,
    pub default_interface: Option<String>,
    pub default_interface_index: Option<u32>,
}

impl Default for NetInfo {
    fn default() -> Self {
        Self {
            default_ipv4_gateway: None,
            default_ipv6_gateway: None,
            default_ipv4_address: None,
            default_ipv6_address: None,
            ipv4_forwarding: false,
            ipv6_forwarding: false,
            default_interface: None,
            default_interface_index: None,
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn get_net_info() -> NetInfo {
    let iface = common::cmd::get_default_interface().unwrap();

    let ipv4_gw = common::cmd::get_default_ipv4_gateway().unwrap();
    let ipv6_gw = if *option::ENABLE_IPV6 {
        Some(common::cmd::get_default_ipv6_gateway().unwrap())
    } else {
        None
    };

    let all_interfaces = pnet_datalink::interfaces();
    let ipv4_addr = if let Some(ifa) = all_interfaces
        .iter()
        .find(|ifa| ifa.name == iface && !ifa.ips.is_empty())
    {
        ifa.ips
            .iter()
            .find(|ipn| ipn.is_ipv4())
            .map(|ipn| ipn.ip().to_string())
    } else {
        None
    };
    let ipv6_addr = if *option::ENABLE_IPV6 {
        if let Some(ifa) = all_interfaces
            .iter()
            .find(|ifa| ifa.name == iface && !ifa.ips.is_empty())
        {
            ifa.ips
                .iter()
                .find(|ipn| ipn.is_ipv6())
                .map(|ipn| ipn.ip().to_string())
        } else {
            None
        }
    } else {
        None
    };
    let ipv4_forwarding = common::cmd::get_ipv4_forwarding().unwrap();
    let ipv6_forwarding = if *option::ENABLE_IPV6 {
        common::cmd::get_ipv6_forwarding().unwrap()
    } else {
        false
    };

    NetInfo {
        default_ipv4_gateway: Some(ipv4_gw),
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        ipv4_forwarding,
        ipv6_forwarding,
        default_interface: Some(iface),
        default_interface_index: None,
    }
}

#[cfg(target_os = "windows")]
pub fn get_net_info() -> NetInfo {
    let iface = common::cmd::get_default_interface().ok();
    let iface_index = common::cmd::get_default_interface_index().ok();
    let ipv4_gw = common::cmd::get_default_ipv4_gateway().ok();
    let ipv4_addr = common::cmd::get_default_ipv4_address().ok();
    let ipv6_gw = if *option::ENABLE_IPV6 {
        common::cmd::get_default_ipv6_gateway().ok()
    } else {
        None
    };
    let ipv6_addr = if *option::ENABLE_IPV6 {
        common::cmd::get_default_ipv6_address().ok()
    } else {
        None
    };

    NetInfo {
        default_ipv4_gateway: ipv4_gw,
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        ipv4_forwarding: false,
        ipv6_forwarding: false,
        default_interface: iface,
        default_interface_index: iface_index,
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn post_tun_creation_setup(net_info: &NetInfo) {
    #[allow(unused_variables)]
    if let NetInfo {
        default_ipv4_gateway: Some(ipv4_gw),
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        ipv4_forwarding,
        ipv6_forwarding,
        default_interface: Some(iface),
        default_interface_index: _,
    } = net_info
    {
        use std::net::{Ipv4Addr, Ipv6Addr};
        common::cmd::add_interface_ipv4_address(
            &*option::DEFAULT_TUN_NAME,
            (*option::DEFAULT_TUN_IPV4_ADDR)
                .parse::<Ipv4Addr>()
                .unwrap(),
            (*option::DEFAULT_TUN_IPV4_GW).parse::<Ipv4Addr>().unwrap(),
            (*option::DEFAULT_TUN_IPV4_MASK)
                .parse::<Ipv4Addr>()
                .unwrap(),
        )
        .unwrap();
        common::cmd::delete_default_ipv4_route(None).unwrap();

        common::cmd::add_default_ipv4_route(
            option::DEFAULT_TUN_IPV4_GW.parse::<Ipv4Addr>().unwrap(),
            iface.clone(),
            true,
        )
        .unwrap();
        common::cmd::add_default_ipv4_route(
            ipv4_gw.parse::<Ipv4Addr>().unwrap(),
            iface.clone(),
            false,
        )
        .unwrap();

        #[cfg(target_os = "linux")]
        {
            if let Some(a) = ipv4_addr {
                common::cmd::add_default_ipv4_rule(a.parse::<Ipv4Addr>().unwrap()).unwrap();
            }
        }

        if *option::GATEWAY_MODE && !ipv4_forwarding {
            common::cmd::set_ipv4_forwarding(true).unwrap();
        }

        if *option::ENABLE_IPV6 {
            common::cmd::add_interface_ipv6_address(
                &*option::DEFAULT_TUN_NAME,
                option::DEFAULT_TUN_IPV6_ADDR.parse::<Ipv6Addr>().unwrap(),
                *option::DEFAULT_TUN_IPV6_PREFIXLEN,
            )
            .unwrap();

            if let Some(ipv6_gw) = ipv6_gw {
                common::cmd::delete_default_ipv6_route(None).unwrap();
                common::cmd::add_default_ipv6_route(
                    option::DEFAULT_TUN_IPV6_GW.parse::<Ipv6Addr>().unwrap(),
                    iface.clone(),
                    true,
                )
                .unwrap();
                common::cmd::add_default_ipv6_route(
                    ipv6_gw.parse::<Ipv6Addr>().unwrap(),
                    iface.clone(),
                    false,
                )
                .unwrap();
            }

            #[cfg(target_os = "linux")]
            {
                if let Some(a) = ipv6_addr {
                    common::cmd::add_default_ipv6_rule(a.parse::<Ipv6Addr>().unwrap()).unwrap();
                }
            }

            if *option::GATEWAY_MODE && !ipv6_forwarding {
                common::cmd::set_ipv6_forwarding(true).unwrap();
            }
        }

        #[cfg(target_os = "linux")]
        {
            if *option::GATEWAY_MODE {
                common::cmd::add_iptable_forward(&*option::DEFAULT_TUN_NAME).unwrap();
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub fn post_tun_creation_setup(net_info: &NetInfo) {
    use std::net::Ipv4Addr;

    let Some(ipv4_gw) = &net_info.default_ipv4_gateway else {
        log::warn!("skip Windows TUN route setup: missing default IPv4 gateway");
        return;
    };
    let Ok(original_gateway) = ipv4_gw.parse::<Ipv4Addr>() else {
        log::warn!(
            "skip Windows TUN route setup: invalid default IPv4 gateway {}",
            ipv4_gw
        );
        return;
    };

    let tun_name = &*option::DEFAULT_TUN_NAME;
    let tun_addr = option::DEFAULT_TUN_IPV4_ADDR.parse::<Ipv4Addr>().unwrap();
    let tun_gw = option::DEFAULT_TUN_IPV4_GW.parse::<Ipv4Addr>().unwrap();
    let tun_mask = option::DEFAULT_TUN_IPV4_MASK.parse::<Ipv4Addr>().unwrap();

    log::info!(
        "Windows TUN route setup: interface={}, address={}, gateway={}, mask={}",
        tun_name,
        tun_addr,
        tun_gw,
        tun_mask
    );
    if let Ok(diag) = common::cmd::windows_tun_diagnostics() {
        log::info!("Windows TUN diagnostics before route setup:\n{}", diag);
    }

    if let Ok(bypass) = std::env::var("VPN_BYPASS_IPV4") {
        for item in bypass.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(address) = item.parse::<Ipv4Addr>() {
                if let Err(e) = common::cmd::add_host_ipv4_route(
                    address,
                    original_gateway,
                    net_info.default_interface.clone(),
                ) {
                    log::warn!("add Windows bypass route for {} failed: {}", address, e);
                } else {
                    log::info!(
                        "Windows bypass route added: {} via gateway {}",
                        address,
                        original_gateway
                    );
                }
            }
        }
    }

    let _ = common::cmd::delete_split_ipv4_default_routes();
    if let Err(e) = common::cmd::add_split_ipv4_default_routes(tun_gw, tun_name.to_string()) {
        log::warn!("add Windows TUN split default routes failed: {}", e);
    }
    if let Ok(diag) = common::cmd::windows_tun_diagnostics() {
        log::info!("Windows TUN diagnostics after route setup:\n{}", diag);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn post_tun_completion_setup(net_info: &NetInfo) {
    #[allow(unused_variables)]
    if let NetInfo {
        default_ipv4_gateway: Some(ipv4_gw),
        default_ipv6_gateway: ipv6_gw,
        default_ipv4_address: ipv4_addr,
        default_ipv6_address: ipv6_addr,
        ipv4_forwarding,
        ipv6_forwarding,
        default_interface: Some(iface),
        default_interface_index: _,
    } = &net_info
    {
        use std::net::{Ipv4Addr, Ipv6Addr};
        common::cmd::delete_default_ipv4_route(None).unwrap();
        common::cmd::delete_default_ipv4_route(Some(iface.clone())).unwrap();

        common::cmd::add_default_ipv4_route(
            ipv4_gw.parse::<Ipv4Addr>().unwrap(),
            iface.clone(),
            true,
        )
        .unwrap();

        #[cfg(target_os = "linux")]
        {
            if let Some(a) = ipv4_addr {
                common::cmd::delete_default_ipv4_rule(a.parse::<Ipv4Addr>().unwrap()).unwrap();
            }
        }

        if *option::GATEWAY_MODE && !ipv4_forwarding {
            common::cmd::set_ipv4_forwarding(false).unwrap();
        }

        if *option::ENABLE_IPV6 {
            if let Some(ipv6_gw) = ipv6_gw {
                common::cmd::delete_default_ipv6_route(None).unwrap();
                common::cmd::delete_default_ipv6_route(Some(iface.clone())).unwrap();
                common::cmd::add_default_ipv6_route(
                    ipv6_gw.parse::<Ipv6Addr>().unwrap(),
                    iface.clone(),
                    true,
                )
                .unwrap();
            }

            #[cfg(target_os = "linux")]
            {
                if let Some(a) = ipv6_addr {
                    common::cmd::delete_default_ipv6_rule(a.parse::<Ipv6Addr>().unwrap()).unwrap();
                }
            }

            if *option::GATEWAY_MODE && !ipv6_forwarding {
                common::cmd::set_ipv6_forwarding(false).unwrap();
            }
        }

        #[cfg(target_os = "linux")]
        {
            if *option::GATEWAY_MODE {
                common::cmd::delete_iptable_forward(&*option::DEFAULT_TUN_NAME).unwrap();
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub fn post_tun_completion_setup(net_info: &NetInfo) {
    use std::net::Ipv4Addr;

    if let Ok(bypass) = std::env::var("VPN_BYPASS_IPV4") {
        for item in bypass.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Ok(address) = item.parse::<Ipv4Addr>() {
                if let Err(e) = common::cmd::delete_host_ipv4_route(address) {
                    log::warn!("delete Windows bypass route for {} failed: {}", address, e);
                }
            }
        }
    }

    let _ = common::cmd::delete_split_ipv4_default_routes();
    if let Ok(diag) = common::cmd::windows_tun_diagnostics() {
        log::info!("Windows TUN diagnostics after cleanup:\n{}", diag);
    }
    if let (Some(ipv4_gw), Some(iface)) =
        (&net_info.default_ipv4_gateway, &net_info.default_interface)
    {
        if let Ok(gateway) = ipv4_gw.parse::<Ipv4Addr>() {
            if let Err(e) = common::cmd::add_default_ipv4_route(gateway, iface.clone(), false) {
                log::warn!("ensure Windows default route failed: {}", e);
            }
        }
    }
}

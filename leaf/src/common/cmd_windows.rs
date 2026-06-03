use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::process::CommandExt;
use std::process::Command;

use anyhow::{anyhow, Result};

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct DefaultIpv4RouteSummary {
    pub gateway: Option<String>,
    pub interface: Option<String>,
    pub interface_index: Option<u32>,
    pub address: Option<String>,
}

fn hidden_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

fn run_status(mut command: Command) -> Result<()> {
    let output = command.output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Err(anyhow!(
            "command exited with status {}: {}{}{}",
            output.status,
            stderr,
            if stderr.is_empty() || stdout.is_empty() {
                ""
            } else {
                "; "
            },
            stdout
        ))
    }
}

fn powershell(script: &str) -> Result<String> {
    let output = hidden_command("powershell.exe")
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-WindowStyle")
        .arg("Hidden")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(script)
        .output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "powershell failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn interface_index(name: &str) -> Result<String> {
    if name == "FlutersTun" {
        if let Ok(index) = std::env::var("LEAF_TUN_INTERFACE_INDEX") {
            let index = index.trim();
            if !index.is_empty() {
                return Ok(index.to_string());
            }
        }
    }

    let escaped = name.replace('\'', "''");
    let mut script = format!(
        "$name = '{}'; \
         $adapter = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1; ",
        escaped
    );
    if name == "FlutersTun" {
        script.push_str(
            "if (-not $adapter) { $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like '*Wintun*' -or $_.Name -like '*Wintun*' -or $_.Name -like '*Tun*' } | Select-Object -First 1; } \
             if (-not $adapter) { $ip = Get-NetIPAddress -AddressFamily IPv4 -IPAddress '10.255.0.2' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($ip) { $adapter = Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex -ErrorAction SilentlyContinue; } } ",
        );
    }
    script.push_str(
        "if ($adapter) { [string]$adapter.InterfaceIndex } else { throw 'adapter not found' }",
    );
    Ok(powershell(&script)?.trim().to_string())
}

pub fn get_interface_index(name: &str) -> Result<u32> {
    let name = name.trim();
    let name = name.strip_prefix("ifindex:").unwrap_or(name);
    if let Ok(index) = name.parse::<u32>() {
        return Ok(index);
    }

    let index = interface_index(name)?;
    index
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow!("invalid interface index for {}: {}", name, e))
}

pub fn windows_tun_diagnostics() -> Result<String> {
    let index_filter = std::env::var("LEAF_TUN_INTERFACE_INDEX").ok();
    let index_script = index_filter
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("$tunIndex = {}; ", value.trim()))
        .unwrap_or_else(|| "$tunIndex = $null; ".to_string());
    powershell(&format!(
        "{}\
         $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ ($tunIndex -and $_.InterfaceIndex -eq $tunIndex) -or $_.InterfaceDescription -like '*Wintun*' -or $_.Name -like '*Wintun*' -or $_.Name -like '*Tun*' }} | Select-Object Name,InterfaceDescription,InterfaceIndex,Status,InterfaceMetric; \
         $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ ($tunIndex -and $_.InterfaceIndex -eq $tunIndex) -or $_.IPAddress -eq '10.255.0.2' -or $_.InterfaceAlias -like '*Tun*' -or $_.InterfaceAlias -like '*Wintun*' }} | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength; \
         $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ $_.DestinationPrefix -eq '0.0.0.0/1' -or $_.DestinationPrefix -eq '128.0.0.0/1' -or $_.DestinationPrefix -eq '0.0.0.0/0' }} | Sort-Object DestinationPrefix,RouteMetric,InterfaceMetric | Select-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric,InterfaceMetric,State; \
         'TunIndex:'; $tunIndex | Out-String; \
         'Adapters:'; $adapters | Format-Table -AutoSize | Out-String; \
         'IPv4:'; $ips | Format-Table -AutoSize | Out-String; \
         'Routes:'; $routes | Format-Table -AutoSize | Out-String",
        index_script
    ))
}

pub fn windows_tun_diagnostics_enabled() -> bool {
    matches!(
        std::env::var("WINDOWS_TUN_DIAGNOSTICS")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub fn get_default_ipv4_gateway() -> Result<String> {
    powershell("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop)")
}

pub fn get_default_ipv4_route_summary() -> Result<DefaultIpv4RouteSummary> {
    let output = powershell(
        "$tunIndex = $env:LEAF_TUN_INTERFACE_INDEX; \
         $routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object RouteMetric, InterfaceMetric; \
         $route = $routes | Where-Object { \
            $isTun = $false; \
            if ($tunIndex -and [string]$_.InterfaceIndex -eq [string]$tunIndex) { $isTun = $true } \
            $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; \
            if ($adapter -and ($adapter.Name -eq 'FlutersTun' -or $adapter.Name -like '*Wintun*' -or $adapter.InterfaceDescription -like '*Wintun*' -or $adapter.InterfaceDescription -like '*Tunnel*')) { $isTun = $true } \
            $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '10.255.0.2'} | Select-Object -First 1; \
            (-not $isTun) -and ($ip -ne $null) \
         } | Select-Object -First 1; \
         if (-not $route) { $route = $routes | Select-Object -First 1; } \
         $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue; \
         $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '10.255.0.2'} | Select-Object -First 1; \
         [string]$route.NextHop; [string]$route.InterfaceIndex; if ($adapter) { [string]$adapter.Name } else { '' }; if ($ip) { [string]$ip.IPAddress } else { '' }",
    )?;
    let mut lines = output.lines().map(str::trim);
    let gateway = lines
        .next()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let interface_index = lines.next().and_then(|value| value.parse::<u32>().ok());
    let interface = lines
        .next()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let address = lines
        .next()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(DefaultIpv4RouteSummary {
        gateway,
        interface,
        interface_index,
        address,
    })
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    powershell("(Get-NetRoute -DestinationPrefix '::/0' | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop)")
}

pub fn get_default_interface() -> Result<String> {
    get_default_ipv4_route_summary()?
        .interface
        .ok_or_else(|| anyhow!("default interface not found"))
}

pub fn get_default_interface_index() -> Result<u32> {
    get_default_ipv4_route_summary()?
        .interface_index
        .ok_or_else(|| anyhow!("default interface index not found"))
}

pub fn get_default_ipv4_address() -> Result<String> {
    get_default_ipv4_route_summary()?
        .address
        .ok_or_else(|| anyhow!("default IPv4 address not found"))
}

pub fn get_default_ipv6_address() -> Result<String> {
    powershell("$route = Get-NetRoute -DestinationPrefix '::/0' | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; (Get-NetIPAddress -AddressFamily IPv6 -InterfaceIndex $route.InterfaceIndex | Select-Object -First 1 -ExpandProperty IPAddress)")
}

pub fn add_interface_ipv4_address(
    name: &str,
    addr: Ipv4Addr,
    gw: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<()> {
    let mut command = hidden_command("netsh.exe");
    command
        .arg("interface")
        .arg("ip")
        .arg("set")
        .arg("address")
        .arg(format!("name={}", name))
        .arg("static")
        .arg(addr.to_string())
        .arg(mask.to_string())
        .arg(gw.to_string());
    run_status(command)
}

pub fn add_interface_ipv6_address(name: &str, addr: Ipv6Addr, prefixlen: i32) -> Result<()> {
    let mut command = hidden_command("netsh.exe");
    command
        .arg("interface")
        .arg("ipv6")
        .arg("add")
        .arg("address")
        .arg(format!("interface={}", name))
        .arg(format!("address={}/{}", addr, prefixlen));
    run_status(command)
}

pub fn optimize_tun_interface(name: &str) -> Result<()> {
    let index = interface_index(name)?;
    let mut first_error = None;

    let mut disable_router_discovery = hidden_command("netsh.exe");
    disable_router_discovery
        .arg("interface")
        .arg("ipv6")
        .arg("set")
        .arg("interface")
        .arg(index.to_string())
        .arg("routerdiscovery=disabled")
        .arg("dadtransmits=0")
        .arg("managedaddress=disabled")
        .arg("otherstateful=disabled");
    if let Err(e) = run_status(disable_router_discovery) {
        first_error.get_or_insert(e);
    }

    let mut disable_forwarding = hidden_command("netsh.exe");
    disable_forwarding
        .arg("interface")
        .arg("ipv6")
        .arg("set")
        .arg("interface")
        .arg(index.to_string())
        .arg("forwarding=disabled")
        .arg("advertise=disabled");
    if let Err(e) = run_status(disable_forwarding) {
        first_error.get_or_insert(e);
    }

    if let Some(e) = first_error {
        Err(e)
    } else {
        Ok(())
    }
}

pub fn add_default_ipv4_route(gateway: Ipv4Addr, interface: String, primary: bool) -> Result<()> {
    let metric = if primary { "1" } else { "50" };
    let mut command = hidden_command("route.exe");
    command
        .arg("add")
        .arg("0.0.0.0")
        .arg("mask")
        .arg("0.0.0.0")
        .arg(gateway.to_string())
        .arg("metric")
        .arg(metric);
    if let Ok(index) = interface_index(&interface) {
        command.arg("if").arg(index);
    }
    run_status(command)
}

pub fn add_split_ipv4_default_routes(_gateway: Ipv4Addr, interface: String) -> Result<()> {
    let index = interface_index(&interface)?;
    log::info!("Windows TUN route interface index: {}", index);

    let mut delete_default = hidden_command("route.exe");
    delete_default
        .arg("delete")
        .arg("0.0.0.0")
        .arg("mask")
        .arg("0.0.0.0")
        .arg("0.0.0.0");
    let _ = run_status(delete_default);

    for (destination, mask, label) in [
        ("0.0.0.0", "128.0.0.0", "0.0.0.0/1"),
        ("128.0.0.0", "128.0.0.0", "128.0.0.0/1"),
    ] {
        let mut delete = hidden_command("route.exe");
        delete
            .arg("delete")
            .arg(destination)
            .arg("mask")
            .arg(mask)
            .arg("0.0.0.0");
        let _ = run_status(delete);

        let mut add = hidden_command("route.exe");
        add.arg("add")
            .arg(destination)
            .arg("mask")
            .arg(mask)
            .arg("0.0.0.0")
            .arg("metric")
            .arg("1")
            .arg("if")
            .arg(index.to_string());
        run_status(add)?;
        log::info!(
            "Windows TUN split route added: {} via interface {}",
            label,
            index
        );
    }
    Ok(())
}

pub fn delete_split_ipv4_default_routes() -> Result<()> {
    let mut first_error = None;
    for (destination, mask) in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
        let mut command = hidden_command("route.exe");
        command.arg("delete").arg(destination).arg("mask").arg(mask);
        if let Err(e) = run_status(command) {
            first_error.get_or_insert(e);
        }
    }
    if let Some(e) = first_error {
        Err(e)
    } else {
        Ok(())
    }
}

pub fn add_default_ipv6_route(gateway: Ipv6Addr, interface: String, primary: bool) -> Result<()> {
    let metric = if primary { "1" } else { "5" };
    let mut command = hidden_command("netsh.exe");
    command
        .arg("interface")
        .arg("ipv6")
        .arg("add")
        .arg("route")
        .arg("::/0")
        .arg(format!("interface={}", interface))
        .arg(format!("nexthop={}", gateway))
        .arg(format!("metric={}", metric));
    run_status(command)
}

pub fn delete_default_ipv4_route(_ifscope: Option<String>) -> Result<()> {
    let mut command = hidden_command("route.exe");
    command
        .arg("delete")
        .arg("0.0.0.0")
        .arg("mask")
        .arg("0.0.0.0");
    run_status(command)
}

pub fn delete_default_ipv6_route(ifscope: Option<String>) -> Result<()> {
    let mut command = hidden_command("netsh.exe");
    command
        .arg("interface")
        .arg("ipv6")
        .arg("delete")
        .arg("route")
        .arg("::/0");
    if let Some(interface) = ifscope {
        command.arg(format!("interface={}", interface));
    }
    run_status(command)
}

pub fn add_host_ipv4_routes(
    addresses: &[Ipv4Addr],
    gateway: Ipv4Addr,
    interface: Option<String>,
) -> Result<()> {
    if addresses.is_empty() {
        return Ok(());
    }
    let index = interface
        .as_deref()
        .and_then(|value| get_interface_index(value).ok());
    let mut first_error = None;
    for address in addresses {
        let mut delete = hidden_command("route.exe");
        delete
            .arg("delete")
            .arg(address.to_string())
            .arg("mask")
            .arg("255.255.255.255");
        let _ = run_status(delete);

        let mut add = hidden_command("route.exe");
        add.arg("add")
            .arg(address.to_string())
            .arg("mask")
            .arg("255.255.255.255")
            .arg(gateway.to_string())
            .arg("metric")
            .arg("1");
        if let Some(index) = index {
            add.arg("if").arg(index.to_string());
        }
        if let Err(e) = run_status(add) {
            first_error.get_or_insert(e);
        }
    }
    if let Some(e) = first_error {
        Err(e)
    } else {
        Ok(())
    }
}

pub fn add_host_ipv4_route(
    address: Ipv4Addr,
    gateway: Ipv4Addr,
    interface: Option<String>,
) -> Result<()> {
    add_host_ipv4_routes(&[address], gateway, interface)
}

pub fn delete_host_ipv4_route(address: Ipv4Addr) -> Result<()> {
    let mut command = hidden_command("route.exe");
    command
        .arg("delete")
        .arg(address.to_string())
        .arg("mask")
        .arg("255.255.255.255");
    run_status(command)
}

pub fn set_interface_dns(name: &str, dns: Ipv4Addr) -> Result<()> {
    let mut command = hidden_command("netsh.exe");
    command
        .arg("interface")
        .arg("ip")
        .arg("set")
        .arg("dns")
        .arg(format!("name={}", name))
        .arg("static")
        .arg(dns.to_string());
    run_status(command)
}

pub fn get_ipv4_forwarding() -> Result<bool> {
    Ok(false)
}

pub fn get_ipv6_forwarding() -> Result<bool> {
    Ok(false)
}

pub fn set_ipv4_forwarding(_val: bool) -> Result<()> {
    Ok(())
}

pub fn set_ipv6_forwarding(_val: bool) -> Result<()> {
    Ok(())
}

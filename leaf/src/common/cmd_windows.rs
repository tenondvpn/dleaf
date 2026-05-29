use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};

const CREATE_NO_WINDOW: u32 = 0x08000000;

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

pub fn get_default_ipv4_gateway() -> Result<String> {
    powershell("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop)")
}

pub fn get_default_ipv6_gateway() -> Result<String> {
    powershell("(Get-NetRoute -DestinationPrefix '::/0' | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop)")
}

pub fn get_default_interface() -> Result<String> {
    powershell("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 | Get-NetAdapter | Select-Object -First 1 -ExpandProperty Name)")
}

pub fn get_default_interface_index() -> Result<u32> {
    powershell("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 -ExpandProperty InterfaceIndex)")?
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow!("invalid default interface index: {}", e))
}

pub fn get_default_ipv4_address() -> Result<String> {
    powershell("$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex | Where-Object {$_.IPAddress -notlike '169.254.*'} | Select-Object -First 1 -ExpandProperty IPAddress)")
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
    let mut index = None;
    for _ in 0..20 {
        match interface_index(&interface) {
            Ok(value) if !value.trim().is_empty() => {
                index = Some(value.trim().to_string());
                break;
            }
            _ => thread::sleep(Duration::from_millis(250)),
        }
    }
    let index = index.ok_or_else(|| anyhow!("TUN adapter interface index not found"))?;
    log::info!("Windows TUN route interface index: {}", index);
    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
        powershell(&format!(
            "Get-NetRoute -DestinationPrefix '{}' -InterfaceIndex {} -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; New-NetRoute -DestinationPrefix '{}' -InterfaceIndex {} -NextHop '0.0.0.0' -RouteMetric 0 -PolicyStore ActiveStore | Out-Null; Get-NetRoute -DestinationPrefix '{}' -InterfaceIndex {} -ErrorAction Stop | Select-Object -First 1 DestinationPrefix,NextHop,InterfaceIndex,RouteMetric,InterfaceMetric | Format-List | Out-String",
            prefix, index, prefix, index, prefix, index
        ))?;
        log::info!(
            "Windows TUN split route added: {} via interface {}",
            prefix,
            index
        );
    }
    Ok(())
}

pub fn delete_split_ipv4_default_routes() -> Result<()> {
    let mut first_error = None;
    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
        if let Err(e) = powershell(&format!(
            "Get-NetRoute -DestinationPrefix '{}' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue",
            prefix
        )) {
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
    let addresses = addresses
        .iter()
        .map(|address| format!("'{}'", address))
        .collect::<Vec<_>>()
        .join(",");
    let gateway = gateway.to_string();
    let interface_script = if let Some(interface) = interface {
        let escaped = interface.replace('\'', "''");
        format!(
            "$adapter = Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue | Select-Object -First 1; ",
            escaped
        )
    } else {
        "$adapter = $null; ".to_string()
    };
    let script = format!(
        "{}\
         if (-not $adapter) {{ $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop '{}' -ErrorAction SilentlyContinue | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; if ($route) {{ $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue; }} }} \
         if (-not $adapter) {{ throw 'physical adapter not found for bypass route' }} \
         $addresses = @({}); \
         foreach ($address in $addresses) {{ \
             $prefix = \"$address/32\"; \
             Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; \
             New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $adapter.InterfaceIndex -NextHop '{}' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null; \
         }}",
        interface_script, gateway, addresses, gateway
    );
    powershell(&script).map(|_| ())
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

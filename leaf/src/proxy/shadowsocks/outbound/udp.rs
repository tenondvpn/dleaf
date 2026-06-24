use std::net::Ipv4Addr;
use std::{cmp::min, convert::TryFrom, io, sync::Arc};
use std::sync::atomic::{AtomicU64, Ordering};
extern crate rand;
use crate::common;
use crate::{
    proxy::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use log::*;
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::Rng;
use sha2::{Digest, Sha256};

use super::shadow::{self, ShadowedDatagram};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
}

fn pick_route_address(tmp_vec: &[&str]) -> Option<String> {
    let route_vec: Vec<&str> = tmp_vec
        .get(1)
        .map(|routes| {
            routes
                .split("N")
                .filter(|route| route.parse::<Ipv4Addr>().is_ok())
                .collect()
        })
        .unwrap_or_else(Vec::new);

    if route_vec.is_empty() {
        None
    } else {
        let mut rng = rand::thread_rng();
        let rand_idx = rng.gen_range(0..route_vec.len());
        Some(route_vec[rand_idx].to_string())
    }
}

fn connect_via_vpn_server(vec: &[&str], route_address: &Option<String>) -> bool {
    route_address.is_none() || (vec.len() >= 8 && vec[7].parse::<u32>().unwrap() != 0)
}

fn udp_via_connector(tmp_vec: &[&str]) -> bool {
    // password format: ...M<routes>Ctcp_via_connector=1Cudp_via_connector=1
    tmp_vec
        .get(1)
        .map(|s| s.contains("udp_via_connector=1"))
        .unwrap_or(false)
}

fn select_connect_addr(vec: &[&str], tmp_vec: &[&str]) -> (String, u16, bool) {
    // If udp_via_connector flag is set, route UDP through local p2p connector
    if udp_via_connector(tmp_vec) {
        return ("127.0.0.1".to_string(), 1091, false);
    }
    let route_address = pick_route_address(tmp_vec);
    let use_vpn_server = connect_via_vpn_server(vec, &route_address);
    let address = if use_vpn_server {
        match vec.get(1) {
            Some(a) => a.to_string(),
            None => return (String::new(), 0, true),
        }
    } else {
        route_address.unwrap()
    };
    let port = if use_vpn_server {
        common::sync_valid_routes::get_port_with_ip(address.clone(), 10000, 35000)
    } else {
        common::sync_valid_routes::get_port_with_ip(address.clone(), 35000, 65000)
    };

    (address, port, use_vpn_server)
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        let tmp_vec: Vec<&str> = self.password.splitn(2, "M").collect();
        let tmp_pass = tmp_vec[0].to_string();
        let vec: Vec<&str> = tmp_pass.split("-").collect();
        let (address, port, _) = select_connect_addr(&vec, &tmp_vec);

        Some(OutboundConnect::Proxy(address.clone(), port))
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Datagram
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        let tmp_vec: Vec<&str> = self.password.splitn(2, "M").collect();
        let tmp_pass = tmp_vec[0].to_string();
        let vec: Vec<&str> = tmp_pass.split("-").collect();
        if vec.len() < 5 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ss password format"));
        }
        let (address, port, use_vpn_server) = select_connect_addr(&vec, &tmp_vec);
        if address.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no valid ss address"));
        }
        let via_connector = udp_via_connector(&tmp_vec);
        if via_connector {
            info!("[UDP] routing via connector 127.0.0.1:1091");
        }
        let mut tmp_vpn_ip = 0;
        let mut tmp_vpn_port = vec[2].parse::<u16>().unwrap_or(0);
        if via_connector {
            // connector handles routing; don't set vpn_ip/vpn_port header
            tmp_vpn_ip = 0;
            tmp_vpn_port = 0;
        } else if use_vpn_server {
            tmp_vpn_port = 0;
        } else {
            let addr: Ipv4Addr = vec[1].to_string().parse().unwrap();
            tmp_vpn_ip = addr.into();
            tmp_vpn_port =
                common::sync_valid_routes::get_port_with_ip(vec[1].to_string(), 10000, 35000);
        }

        let server_addr = SocksAddr::try_from((&address.clone(), port))?;
        let socket = if let Some(OutboundTransport::Datagram(socket)) = transport {
            socket
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid input"));
        };

        let tmp_ps = vec[0].to_string();
        let tmp_pk = vec[3];
        let tmp_ver = vec[4];
        let tmp_ex_route_ip = 0;
        let tmp_ex_route_port = 0;
        let dgram = ShadowedDatagram::new(&self.cipher, &tmp_ps)?;
        let destination = match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                Some(SocksAddr::Domain(domain.to_owned(), port.to_owned()))
            }
            _ => None,
        };

        Ok(Box::new(Datagram {
            dgram,
            socket,
            destination,
            server_addr,
            vpn_ip: tmp_vpn_ip,
            vpn_port: tmp_vpn_port,
            pk_str: tmp_pk.to_string(),
            ver: tmp_ver.to_string(),
            ex_route_ip: tmp_ex_route_ip,
            ex_route_port: tmp_ex_route_port,
            address: address,
            plain_passthrough: via_connector,
        }))
    }
}

pub struct Datagram {
    pub dgram: ShadowedDatagram,
    pub socket: Box<dyn OutboundDatagram>,
    pub destination: Option<SocksAddr>,
    pub server_addr: SocksAddr,
    pub vpn_ip: u32,
    pub vpn_port: u16,
    pub pk_str: String,
    pub ver: String,
    pub ex_route_ip: u32,
    pub ex_route_port: u16,
    pub address: String,
    pub plain_passthrough: bool,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let dgram = Arc::new(self.dgram);
        let (r, s) = self.socket.split();
        (
            Box::new(DatagramRecvHalf(dgram.clone(), r, self.destination, self.plain_passthrough)),
            Box::new(DatagramSendHalf {
                dgram,
                send_half: s,
                server_addr: self.server_addr,
                vpn_ip: self.vpn_ip,
                vpn_port: self.vpn_port,
                pk_str: self.pk_str,
                ver: self.ver,
                ex_route_ip: self.ex_route_ip,
                ex_route_port: self.ex_route_port,
                address: self.address,
                plain_passthrough: self.plain_passthrough,
            }),
        )
    }
}

pub struct DatagramRecvHalf(
    Arc<ShadowedDatagram>,
    Box<dyn OutboundDatagramRecvHalf>,
    Option<SocksAddr>,
    bool,
);

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let mut buf2 = BytesMut::new();
        buf2.resize(2 * 1024, 0);
        let (n, _) = self.1.recv_from(&mut buf2).await?;
        buf2.resize(n, 0);
        let plaintext = if self.3 {
            buf2.freeze()
        } else {
            self.0.decrypt(buf2).map_err(|_| shadow::crypto_err())?
        };
        let src_addr = SocksAddr::try_from((&plaintext[..], SocksAddrWireType::PortLast))?;
        let payload_len = plaintext.len() - src_addr.size();
        let to_write = min(payload_len, buf.len());
        if to_write < payload_len {
            warn!("truncated udp packet, please report this issue");
        }
        buf[..to_write].copy_from_slice(&plaintext[src_addr.size()..src_addr.size() + to_write]);
        if self.2.is_some() {
            // must be a domain destination
            Ok((to_write, self.2.as_ref().unwrap().clone()))
        } else {
            Ok((to_write, src_addr))
        }
    }
}

pub struct DatagramSendHalf {
    dgram: Arc<ShadowedDatagram>,
    send_half: Box<dyn OutboundDatagramSendHalf>,
    server_addr: SocksAddr,
    vpn_ip: u32,
    vpn_port: u16,
    pk_str: String,
    ver: String,
    ex_route_ip: u32,
    ex_route_port: u16,
    address: String,
    plain_passthrough: bool,
}

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        static CONNECTOR_UDP_SENDS: AtomicU64 = AtomicU64::new(0);
        if self.address == "127.0.0.1" {
            let n = CONNECTOR_UDP_SENDS.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n % 100 == 0 {
                info!(
                    "[UDP-CONNECTOR] uplink packet {} to {}:{} bytes={} dst={}",
                    n,
                    self.address,
                    self.server_addr.port(),
                    buf.len(),
                    target
                );
            }
        }
        let mut buf2 = BytesMut::new();
        target.write_buf(&mut buf2, SocksAddrWireType::PortLast);
        buf2.put_slice(buf);
        let payload = if self.plain_passthrough {
            buf2.freeze()
        } else {
            self.dgram.encrypt(buf2).map_err(|_| shadow::crypto_err())?
        };
        let n2: u8 = thread_rng().gen_range(6..16);

        let hash_address = if self.vpn_port != 0 {
            Ipv4Addr::from(self.vpn_ip).to_string()
        } else {
            self.address.clone()
        };

        // Use res_hash (32 bytes) only after TCP has established a session with the server
        // (GetResponseStatus=true means server has cached our pubkey). On first UDP packet,
        // fall back to full 33-byte pubkey so server can build the ECDH key and cache it.
        let pk_bytes: Vec<u8>;
        let use_hash = common::sync_valid_routes::GetResponseStatus(hash_address.clone());
        if use_hash {
            let mut ex_hash = common::sync_valid_routes::GetResponseHash(hash_address.clone());
            if ex_hash.is_empty() {
                let tmp_pk = common::sync_valid_routes::GetClientPk().to_string();
                let tmp_pk_str = hex::decode(tmp_pk[4..70].to_string()).expect("Decoding failed");
                let mut hasher = Sha256::new();
                hasher.update(&tmp_pk_str);
                ex_hash = hex::encode(hasher.finalize());
                common::sync_valid_routes::SetResponseHash(hash_address, ex_hash.clone());
            }
            pk_bytes = hex::decode(ex_hash).expect("Decoding failed");
        } else {
            // First connection: send full compressed pubkey (33 bytes) so server can ECDH
            let tmp_pk = common::sync_valid_routes::GetClientPk().to_string();
            pk_bytes = hex::decode(tmp_pk[4..70].to_string()).expect("Decoding failed");
        }
        let mut buffer1 = BytesMut::with_capacity(32 + n2 as usize + 1 + 32);
        let mut head_size = 0;
        if self.vpn_port != 0 {
            buffer1.put_u32(self.vpn_ip);
            buffer1.put_u16(self.vpn_port);
            head_size += 6;
        }

        buffer1.put_u8(n2);
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(n2 as usize)
            .map(char::from)
            .collect();
        buffer1.put_slice(rand_string[..].as_bytes());
        buffer1.put_slice(&pk_bytes);
        if self.vpn_port != 0 {
            buffer1.put_u8(25);
            buffer1.put_u32(self.vpn_ip);
            buffer1.put_u16(self.vpn_port);
        } else {
            buffer1.put_u8(19);
        }

        buffer1.put_slice(self.ver[..].as_bytes());
        let mut buffer = BytesMut::with_capacity(payload.len() + buffer1.len());
        buffer.put_slice(&buffer1);
        buffer.put_slice(&payload);
        let mut i = 0;
        let pos: usize = head_size + (n2 as usize / 2);
        while i != buffer.len() {
            if i == pos || i == head_size {
                i = i + 1;
                continue;
            }

            buffer[i] = buffer[i] ^ buffer[pos];
            i = i + 1;
        }

        match self.send_half.send_to(&mut buffer, &self.server_addr).await {
            Ok(_) => Ok(buf.len()),
            Err(err) => Err(err),
        }
    }
}

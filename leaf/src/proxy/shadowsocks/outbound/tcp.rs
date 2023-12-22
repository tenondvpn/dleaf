use std::io;
extern crate rand;
use std::net::Ipv4Addr;
use rand::Rng;
use rand::thread_rng;
use rand::distributions::Alphanumeric;
use async_trait::async_trait;
use crate::common;
use tokio::io::AsyncWriteExt;
use bytes::{BufMut, Bytes, BytesMut};
use openssl::sha::Sha256;
use super::shadow::ShadowedStream;
use chrono::DateTime;
use chrono::Local;
use crate::{
    proxy::*,
    session::{Session, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    type Stream = AnyStream;
    fn connect_addr(&self) -> Option<OutboundConnect> {
        let tmp_vec: Vec<&str> = self.password.split("M").collect();
        let tmp_pass = tmp_vec[0].to_string();
        let vec :Vec<&str> = tmp_pass.split("-").collect();
        let mut address = "".to_string();
        let mut port: u16 = 0;
        if (vec.len() >= 8 && vec[7].parse::<u32>().unwrap() != 0) {
            address = vec[1].to_string();
            port = common::sync_valid_routes::get_port_with_ip(address.clone(), 10000, 35000);
        } else {
            let tmp_route = tmp_vec[1].to_string();
            let route_vec: Vec<&str> = tmp_route.split(",").collect();
            let mut rng = rand::thread_rng();
            let rand_idx = rng.gen_range(0..route_vec.len());
            address = route_vec[rand_idx].to_string();
            port = common::sync_valid_routes::get_port_with_ip(address.clone(), 35000, 65000);
            debug!("connect tcp route {} {} rand: {}, len: {}, routes {}, password {}",
                address, port, rand_idx, route_vec.len(), tmp_route, self.password);
        }

        Some(OutboundConnect::Proxy(address.clone(), port))
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        let mut src_stream = stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;
        let tmp_vec: Vec<&str> = self.password.split("M").collect();
        let tmp_pass = tmp_vec[0].to_string();
        let vec :Vec<&str> = tmp_pass.split("-").collect(); 
        let tmp_ps = vec[0].to_string();
        let address = vec[1].to_string();
        let mut pk_str : Vec<u8>;
        if (common::sync_valid_routes::GetResponseStatus(address.clone())) {
            pk_str = hex::decode(common::sync_valid_routes::GetClientPkHash()).expect("Decoding failed");
        } else {
            pk_str = hex::decode(common::sync_valid_routes::GetClientPk()).expect("Decoding failed");
        }

        let ex_hash = common::sync_valid_routes::GetResponseHash(address.clone());
        if (ex_hash.eq("")) {
            let tmp_pk = common::sync_valid_routes::GetClientPk().to_string();
            let tmp_pk_str = hex::decode(tmp_pk[4..70].to_string()).expect("Decoding failed");
            let mut hasher = Sha256::new();
            hasher.update(&tmp_pk_str.clone());
            let result = hasher.finish();
            let result_str = hex::encode(result);
            common::sync_valid_routes::SetResponseHash(address.clone(), result_str);
        }
        
        let mut pk_len = pk_str.len() as u32;
        pk_len += 2;
        let mut n2: u8 = thread_rng().gen_range(7..16) % 16;
        if (n2 >= 16 || n2 < 7) {
            n2 = 9;
        }

        let rand_len = n2 as u32;
        // route ip and port: 6 bytes, rand_len: 1byte, pk len: 2byte
        let mut all_len = 7 + rand_len + pk_len;
        if (vec.len() >= 8 && vec[7].parse::<u32>().unwrap() != 0) {
            all_len -= 6;
        }

        let mut buffer1 = BytesMut::with_capacity(all_len as usize);
        let mut head_size = 0;
        if (vec.len() >= 8) {
            if (vec[7].parse::<u32>().unwrap() == 0) {
                let ex_r_ip = vec[5].parse::<u32>().unwrap();
                if (ex_r_ip != 0) {
                    all_len += 6;
                    head_size += 6;
                    buffer1 = BytesMut::with_capacity(all_len as usize);

                    let tmp_vec: Vec<&str> = self.password.split("M").collect();
                    let tmp_route = tmp_vec[1].to_string();
                    let route_vec: Vec<&str> = tmp_route.split(",").collect();
                    let mut rng = rand::thread_rng();
                    let rand_idx = rng.gen_range(0..route_vec.len());
                    let ex_address = route_vec[rand_idx].to_string();
                    let port = common::sync_valid_routes::get_port_with_ip(ex_address.clone(), 35000, 65000);

                    let addr : Ipv4Addr = ex_address.clone().parse().unwrap();
                    let addr_u32: u32 = addr.into();
                    buffer1.put_u32(addr_u32);
                    buffer1.put_u16(port);
                }
            }
        }

        if (vec.len() >= 8 && vec[7].parse::<u32>().unwrap() == 0) {
            let addr: Ipv4Addr = vec[1].to_string().parse().unwrap();
            let addr_u32: u32 = addr.into();
            let vpn_port = common::sync_valid_routes::get_port_with_ip(vec[1].to_string(), 10000, 35000);
            buffer1.put_u32(addr_u32);
            buffer1.put_u16(vpn_port);
            head_size += 6;
        } 

        buffer1.put_u8(n2);
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(n2 as usize)
            .map(char::from)
            .collect();
        buffer1.put_slice(rand_string[..].as_bytes());
        buffer1.put_u16(pk_len.try_into().unwrap());
        buffer1.put_slice(&pk_str);
        let mut i = 0;
        let pos: usize = head_size + (n2 as usize / 2);
        while i != buffer1.len() {
            if i == pos || i == head_size {
                i = i + 1;
                continue;
            }

            buffer1[i] = buffer1[i] ^ buffer1[pos];
            i = i + 1;
        }

        if (buffer1[head_size] as u8 >= 16) {
            common::sync_valid_routes::SetValidRoutes("DDDDDDDD-0".to_string());
            panic!("this is a terrible mistake!");
        }

        if buffer1.len() != all_len as usize {
            common::sync_valid_routes::SetValidRoutes("DDDDDDDD-1".to_string());
            panic!("this is a terrible mistake!");
        }

        src_stream.write_all(&buffer1).await?;
        let mut stream = ShadowedStream::new(src_stream, &self.cipher, &tmp_ps)?;
        let mut buf = BytesMut::new();
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast);
        stream.write_all(&buf).await?;
        Ok(Box::new(stream))
    }
}


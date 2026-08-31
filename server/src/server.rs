use std::{collections::HashMap, io::Write, net::{Ipv4Addr, SocketAddr}, sync::Arc};

use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UdpSocket, sync::RwLock};
use tun::{AsyncDevice, Device};

use x25519_dalek::{PublicKey, SharedSecret};

use crate::{auth, error::ServerError, interface};




pub struct Server{
    socket:UdpSocket,
    auth:auth::Auth,
    clients:RwLock<HashMap<SocketAddr,SharedSecret>>,
    clients_ip:RwLock<HashMap<Vec<u8>,SocketAddr>>,
    tun_reader:RwLock<tokio::io::ReadHalf<AsyncDevice>>,
    tun_writer:RwLock<tokio::io::WriteHalf<AsyncDevice>>,
}

impl Server{
    pub async fn new ()->Self{
        let socket=CreateServerSocket().await;
        let auth=auth::Auth::new().await;
        let tun=Server::StartInterface().await.unwrap();
        let (tun_reader,tun_writer)=tokio::io::split(tun);
        println!("Created the server-side tun");
        
        Self{
            socket,
            auth,
            clients:RwLock::new(HashMap::new()),
            clients_ip:RwLock::new(HashMap::new()),
            tun_reader:RwLock::new(tun_reader),
            tun_writer:RwLock::new(tun_writer)
        }
    }

    async fn StartInterface()->Result<AsyncDevice, ServerError>{
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let name = "server-tun".to_string();
        let subnet = 24u8;
        let tun=interface::Interface::new(&addr, &name, &subnet).await?;
        Ok(tun)
    }

    pub async fn Start(self:&Arc<Self>){
        let mut buf=[0u8;65535];
        println!("Started the server");
        loop{
            let (buf_size, client_addr) = self.socket.recv_from(&mut buf).await.unwrap();
            
            let payload=&buf[..buf_size];

        

            let (operation_buf,payload)=Simplify(payload.to_vec());

            let(operation_payload,payload)=Simplify(payload);

            self.HandleReq(&operation_buf,&operation_payload,&client_addr).await;
        }
    }


    async fn HandleReq(self:&Arc<Self>,opeartion_buf:&Vec<u8>,operation_payload:&Vec<u8>,client_addr:&SocketAddr){

        println!("Operation_buf is {:?}",opeartion_buf);

        match opeartion_buf.as_slice() {
            b"client_packet"=>{
                // println!("Payload is {:?}",operation_payload);

                let (encrypted_packet,payload)=Simplify(operation_payload.clone());
                println!("Server: Encrypted packet is {:?}",encrypted_packet);
                let gurad=self.clients.read().await;
                let secret=gurad.get(client_addr).unwrap();
                let decrypted_packet=self.auth.Decryptpacket(&encrypted_packet, secret).unwrap();
                println!("Server: Derypted packet= is {:?}",decrypted_packet);

                self.tun_writer.write().await.write_all(&decrypted_packet).await.unwrap();

            }
         
            b"keys_exchange"=>{
                println!("Payload is {:?}",operation_payload);

                let (public_key,private_key)=self.auth.GetKeys();

                let server_public_key_buf=public_key.to_bytes();
                let len=(server_public_key_buf.len() as u64).to_be_bytes();

                let mut buf=Vec::new();
                buf.extend_from_slice(&len);
                buf.extend_from_slice(&server_public_key_buf);





                self.socket.send_to(&buf, client_addr).await.unwrap();




                let (client_public_key ,payload)=Simplify(operation_payload.clone());

                let client_public_key: [u8; 32] = client_public_key
                .try_into()
                .expect("Server public key must be 32 bytes");

                
                let shared=private_key.diffie_hellman(&PublicKey::from(client_public_key));

                self.clients.write().await.insert(*client_addr, shared);



                let (vpn_client_ip,_)=Simplify(payload);

                self.clients_ip.write().await.insert(vpn_client_ip, *client_addr);
            }
         
            _=>{

            }
        }
    }

    pub async fn StartServerTunReader(self: &Arc<Self>){
        let server=Arc::clone(&self);

        tokio::spawn(async move{
            let mut buf =[0u8;65000];
            let mut counter=0;
            println!("Server: Started the tun readaer");
            loop{
                let len=server.tun_reader.write().await.read(&mut buf).await.unwrap();

                let packet=&buf[..len];

                println!("Server:tun reading packet is {:?}",packet);

                // Check IP version
                let version = packet[0] >> 4;

                // Ignore IPv6
                if version == 6 {
                    continue;
                }

                let client_ip: Vec<u8> = packet[16..20].to_vec();
                let ip_guard=server.clients_ip.read().await;
                let client_addr = match ip_guard.get(&client_ip) {
                    Some(addr) => addr,
                    None => continue,
                };
                let clients_guard=server.clients.read().await;
                let secret=clients_guard.get(client_addr).unwrap();

                let encrypted_packet=server.auth.EncryptpPacket(packet, secret, &mut counter);
                
                println!("Server:Sendind Encrypted packet that is {:?}",encrypted_packet);


                let mut final_buf=Vec::new();
                let mut temp=Vec::new();

                let opeariton_buf=b"response_packet";
                let len =(opeariton_buf.len() as u64).to_be_bytes();

                final_buf.extend_from_slice(&len);
                final_buf.extend_from_slice(opeariton_buf);

                let encrypted_len=(encrypted_packet.len() as u64).to_be_bytes();

                temp.extend_from_slice(&encrypted_len);
                temp.extend_from_slice(&encrypted_packet);
                

                let payload_len=(temp.len() as u64).to_be_bytes();
                final_buf.extend_from_slice(&payload_len);
                final_buf.extend_from_slice(&temp);


                server.socket.send_to(&final_buf, client_addr).await.unwrap();
            }

        });
    }
    
}



async fn CreateServerSocket()->UdpSocket{
    let server_addr=std::env::var("server_addr").expect("env var server_addr not found");

    let socket=UdpSocket::bind(server_addr).await.unwrap();

    socket
}



fn Simplify(payload:Vec<u8>)-> (Vec<u8>, Vec<u8>) {
    // Need at least 8 bytes for the length
    if payload.len() < 8 {
        panic!("Buffer is too small to contain length");
    }

    // Read first 8 bytes as big-endian u64
    let len = u64::from_be_bytes(
        payload[0..8]
            .try_into()
            .unwrap()
    ) as usize;

    // Make sure the buffer actually contains the declared data
    if payload.len() < 8 + len {
        panic!("Buffer does not contain enough data");
    }

    // Extract the data after the length
    let data = payload[8..8 + len].to_vec();

    // Everything after that
    let remaining = payload[8 + len..].to_vec();

    (data, remaining)
}






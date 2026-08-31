use std::{io::Read, net::Ipv4Addr, sync::Arc};

use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UdpSocket, sync::RwLock};
use tun::{AsyncDevice, Device};


use crate::{auth, error::{self, ControllerError}, interface};





pub struct Controller{
    tun_reader:RwLock<tokio::io::ReadHalf<AsyncDevice>>,
    tun_writer:RwLock<tokio::io::WriteHalf<AsyncDevice>> ,
    auth:auth::Auth,
    socket:UdpSocket
}


impl Controller {
    pub async fn new()->Self{ 
        let tun=Controller::StartInterface().await.unwrap();
        println!("Created the client-side tun");
        let socket=ConnectToServer().await;
        println!("Created the client-side socket");
        let auth=auth::Auth::new(&socket).await;
        println!("did teh client-side auth");
        


        let (tun_reader,tun_writer)=tokio::io::split(tun);

        Self{
            tun_reader:RwLock::new(tun_reader),
            tun_writer:RwLock::new(tun_writer),
            auth,
            socket
        }
    }

    async fn StartInterface()->Result<AsyncDevice, ControllerError>{
        let addr = Ipv4Addr::new(10, 1, 1, 2);
        let name = "custome-vpn".to_string();
        let subnet = 24u8;
        let tun=interface::Interface::new(&addr, &name, &subnet).await?;
        Ok(tun)
    }

    pub async fn StartRead(self:&Arc<Self>)->Result<(),ControllerError>{
        let mut counter=0;
       
        loop{
            let mut max_packet_size = [0u8; 65535];
            let len=self.tun_reader.write().await.read(&mut max_packet_size).await?;

        
            let packet=&max_packet_size[..len];
            // println!("Client: Original packet length: {}", packet.len());
            // println!("Client: Original packet is {:?}",packet);
            let encrypted_packet=self.auth.EncryptpPacket(packet, &self.auth.shared_secret, &mut counter);
            // println!("Client: Encrypted packet is {:?} wiht counter {}",encrypted_packet,counter);

            let mut final_buf=Vec::new();
            let mut buf=Vec::new();


            let operation_buf=b"client_packet";
            let operation_len=(operation_buf.len() as u64).to_be_bytes();

            final_buf.extend_from_slice(&operation_len);
            final_buf.extend_from_slice(operation_buf);

            let encrypted_packet_len=(encrypted_packet.len() as u64).to_be_bytes();
            buf.extend_from_slice(&encrypted_packet_len);
            buf.extend_from_slice(&encrypted_packet);


            let payload_len=(buf.len() as u64).to_be_bytes();
            final_buf.extend_from_slice(&payload_len);
            final_buf.extend_from_slice(&buf);



            self.socket.send(&final_buf).await.unwrap();

            counter=counter+1;


            // let mut input = String::new();
            // std::io::stdin()
            //     .read_line(&mut input)
            //     .unwrap();
        }
        

        Ok(())
    }

    pub async fn StartServerTunReader(self:&Arc<Self>){
        let mut buf = [0u8; 65535];
        let client=Arc::clone(&self);
        println!("starte the resposen decrypter");

        tokio::spawn(async move{
            loop {
                let (len, _) = client.socket.recv_from(&mut buf).await.unwrap();

                let received = &buf[..len];

                // Get operation
                let (operation, payload) = Simplify(received.to_vec());

                match operation.as_slice() {
                    b"response_packet" => {

                        // Get encrypted packet
                        let (encrypted_packet, _) = Simplify(payload);

                        println!("Client: recived  encrypted = {:?}", encrypted_packet);

                        // SAME shared secret generated during key exchange
                        let decrypted_packet =
                            client.auth
                                .Decryptpacket(
                                    &encrypted_packet,
                                    &client.auth.shared_secret
                                )
                                .unwrap();

                        println!("Client: recieved decrypted = {:?}", decrypted_packet);

                        // Put the original IP packet into TUN
                        client.tun_writer
                            .write().await
                            .write_all(&decrypted_packet)
                            .await
                            .unwrap();
                    }

                    _ => {}
                }
            }
            
        });
         
    }
    


}


async fn ConnectToServer()->UdpSocket{
    let client_addr=std::env::var("client_addr").expect("env var client_addr not found");
    let socket=UdpSocket::bind(client_addr).await.unwrap();

    let server_addr=std::env::var("server_addr").expect("env var server_addr not found");
    socket.connect(server_addr).await.unwrap();
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



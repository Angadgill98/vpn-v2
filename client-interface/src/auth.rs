

use chacha20poly1305::{KeyInit, aead::Aead};
use tokio::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};



pub struct Auth{
    pub shared_secret:SharedSecret
}


impl Auth{
    pub async fn new(udp_socket:&UdpSocket)->Self{

        let (public_key,private_key)=Auth::GetKeys();
        let shared_secret: SharedSecret=Auth::KeysExcahnge(&public_key, private_key, udp_socket).await;
        Self{
            shared_secret
        }
    }


    async fn KeysExcahnge(public_key:&PublicKey,private_key:EphemeralSecret,socket:&UdpSocket)->SharedSecret{
    
        let server_udp_addr=std::env::var("server_addr").expect("env var server_addr not definedd");

        
        let mut final_buf =Vec::new();
        let mut buf =Vec::new();

        
        let op=b"keys_exchange";
        let len=(op.len() as u64).to_be_bytes();

        final_buf.extend_from_slice(&len);
        final_buf.extend_from_slice(op);


        let client_public_key_len_buf=(public_key.as_bytes().len() as u64).to_be_bytes();
        let client_public_key_buf=public_key.as_bytes();


        buf.extend_from_slice(&client_public_key_len_buf);
        buf.extend_from_slice(client_public_key_buf);


        let client_ip=std::env::var("client_addr").unwrap();
        let client_ip_buf=client_ip.as_bytes();
        let len=(client_ip_buf.len()as u64).to_be_bytes();
        

        buf.extend_from_slice(&len);
        buf.extend_from_slice(&client_ip_buf);



        let len=(buf.len()as u64).to_be_bytes();

        final_buf.extend_from_slice(&len);
        final_buf.extend_from_slice(&buf);



        socket.send(&final_buf).await.unwrap();

        //key is 32 bytes
        let  mut  buf=[0u8;65000];
        

        let (len , server_addr)=socket.recv_from(&mut buf).await.unwrap();


        let payload=&buf[..len].to_vec();

        println!("Server public recived as {:?}",payload);

        let (server_public_key,_)=Simplify(payload.clone());

        let server_public_key: [u8; 32] = server_public_key
        .try_into()
        .expect("Server public key must be 32 bytes");


        let shared=private_key.diffie_hellman(&PublicKey::from(server_public_key));
        

        shared

    }


    fn GetKeys()->(x25519_dalek::PublicKey,x25519_dalek::EphemeralSecret){
        let private_key: x25519_dalek::EphemeralSecret=x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);

        let public_key: x25519_dalek::PublicKey=x25519_dalek::PublicKey::from(&private_key);

        (public_key,private_key)
    }


    fn CreateCipher(key:&[u8])->chacha20poly1305::ChaCha20Poly1305{
        let cipher_key=chacha20poly1305::Key::from_slice(key);
        let cipher=chacha20poly1305::ChaCha20Poly1305::new(cipher_key);
        cipher
    }



    pub fn EncryptpPacket(&self,packet:&[u8],secret:&SharedSecret,counter:&mut u64)->Vec<u8>{
        let cipher_key=secret.as_bytes();
        let cipher=Auth::CreateCipher(cipher_key);

        let mut nonce_bytes=[0u8;12];
        nonce_bytes[4..].copy_from_slice(&counter.to_be_bytes());

        let nonce =chacha20poly1305::Nonce::from_slice(&nonce_bytes); 


        let ciphertext=cipher.encrypt(nonce, packet).expect("failed to encrpyt  the packet");

        let mut temp=Vec::new();
        temp.extend_from_slice(nonce);
        temp.extend_from_slice(&ciphertext);

        
        temp
    }


    pub fn Decryptpacket(&self,encrypted_packet:&[u8],secret:&SharedSecret)->Result<Vec<u8>, chacha20poly1305::Error>{
        let nonce_bytes = &encrypted_packet[..12];
        
        let counter = u64::from_be_bytes(
            nonce_bytes[4..12].try_into().unwrap()
        );

        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

        let key = secret.as_bytes();

        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
        
        let ciphertext = &encrypted_packet[12..];
        
        let a=cipher.decrypt(nonce, ciphertext).unwrap();

        Ok(a)
    }




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


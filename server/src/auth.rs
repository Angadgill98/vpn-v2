

use std::sync::Arc;

use chacha20poly1305::{KeyInit, aead::Aead};
use tokio::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};



pub struct Auth{
    // pub public_key:PublicKey,
    // pub private_key:Arc<EphemeralSecret>,

}


impl Auth{
    pub async fn new()->Self{
        

        // let (public_key,private_key)=Auth::GetKeys();
        Self{
            // public_key,
            // private_key:Arc::new(private_key)
        }
    }


   
    pub fn GetKeys(&self)->(x25519_dalek::PublicKey,x25519_dalek::EphemeralSecret){
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

    pub fn SimplifyEncryptedPacket(encrypted_packet:&Vec<u8>){

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


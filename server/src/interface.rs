use std::net::Ipv4Addr;

use futures::TryStreamExt;
use rtnetlink::Handle;
use tun::{AsyncDevice, Device};

use crate::error::ServerError;






pub struct Interface{

}



impl Interface{
    pub async fn new(addr:&Ipv4Addr,name:&String,subnet:&u8)->Result<AsyncDevice,ServerError>{

        let tun={
            Interface::CreateInterface()?
        };

        let handle=Interface::CreateRThandle();
        

        Interface::AssignIP(&handle,addr, name, subnet).await?;

        Interface::UpInterface(&handle, name).await?;
        
        Ok(tun)
    }

    fn CreateInterface()->Result<AsyncDevice,ServerError>{
        let mut config=tun::Configuration::default();
        config.tun_name("server-tun");

        let tun =tun::create_as_async(&config)?;

        Ok(tun)
    }

    async fn AssignIP(handle:&Handle,addr:&Ipv4Addr,name:&String,subnet:&u8)->Result<(),ServerError>{
        

        let index=Interface::Getindex(&handle, name).await?;
        handle
            .address()
            .add(
                index,
                std::net::IpAddr::V4(addr.clone()),
                subnet.clone(),
            )
            .execute()
            .await?;


        Ok(())
    }
   
    async fn Getindex(handle:&Handle,name:&String)->Result<u32,ServerError>{
        let mut links = handle
            .link()
            .get()
            .match_name(name.clone())
            .execute();

        while let Some(link) = links.try_next().await? {
            return Ok(link.header.index);
        };
        Err(ServerError::InterfaceError(format!("Interface {} index not found",name)))
    }

    async fn UpInterface(handle:&Handle,name:&String)->Result<(),ServerError>{
        
        let index=Interface::Getindex(&handle, name).await?;
        handle
        .link()
        .set(index)
        .up()
        .execute()
        .await?;
        
        Ok(())
    }

    fn CreateRThandle()->Handle{
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();

        tokio::spawn(connection);

        handle
    }

    fn GetTun() -> Result<tun::Device, ServerError> {
        let mut config = tun::Configuration::default();

        config
            .tun_name("server-tun")
            .up();

        let tun = tun::create(&config)?;

        Ok(tun)
    }


}
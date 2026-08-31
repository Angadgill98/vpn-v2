use std::sync::Arc;



mod server;
mod auth;
mod interface;
mod error;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let mut server=Arc::new(server::Server::new().await);
    server.StartServerTunReader().await;
    server.Start().await;
}

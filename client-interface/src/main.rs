use std::sync::Arc;









mod client;
mod interface;
mod controller;
mod error;

mod cli;

mod auth;



#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let controller = controller::Controller::new().await;
    let controller=Arc::new(controller);
    let cli=Arc::clone(&controller);
    cli.StartServerTunReader().await;
    cli::run(Arc::clone(&controller)).await;
}

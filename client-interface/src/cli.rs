use std::{io::{self, Write}, sync::Arc};

use crate::controller::Controller;

pub async fn run(controller: Arc<Controller>) {
    loop {
        print!("vpn> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        match input.trim() {
            

            "start" => {
                println!("Starting VPN...");
                
                if let Err(e) = controller.StartRead().await {
                    eprintln!("Error: {:?}", e);
                }
            }

            "help" => {
                println!("Available commands:");
                println!("  start");
                println!("  help");
                println!("  exit");
            }

            "exit" => {
                println!("Exiting...");
                break;
            }

            "" => {}

            command => {
                println!("Unknown command: {}", command);
            }
        }
    }
}
use std::net::SocketAddr;

use tokio::net::TcpListener;

use monas_account::presentation;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = presentation::create_router();

    let port: u16 = std::env::var("MONAS_ACCOUNT_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4002);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("monas-account server listening on http://{addr}");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}



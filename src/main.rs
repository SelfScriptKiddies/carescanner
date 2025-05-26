use carescanner::configuration::Config;
use clap::Parser;

#[tokio::main]
async fn main() {
    let config = Config::parse();
    println!("{:?}", config);
    carescanner::run(config).await;
}

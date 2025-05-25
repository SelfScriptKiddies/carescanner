use carescanner::configuration::Config;
use clap::Parser;

fn main() {
    let config = Config::parse();
    println!("{:?}", config);
    println!("Hello, world!");
}

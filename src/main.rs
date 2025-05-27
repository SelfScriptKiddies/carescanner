use carescanner::configuration::Config;
use clap::Parser;
use log::debug;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let config = Config::parse();
    colog::basic_builder()
        .filter_level(config.logging_level.clone().into())
        .init();

    debug!("{:?}", config);
    carescanner::run(config).await;
}

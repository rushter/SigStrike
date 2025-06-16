// Cobalt Strike Beacon Parser.
// Based on https://github.com/fox-it/dissect.cobaltstrike/tree/main

use sigstrike::cli::run_cli;

#[tokio::main]
async fn main() {
    run_cli(0).await;
}

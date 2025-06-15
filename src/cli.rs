use crate::io::{list_files, process_files};
use clap::{Parser, Subcommand};
use env_logger::Env;
use log::{debug, error, info};
use std::path::PathBuf;
use std::time::Instant;


#[derive(Parser)]
#[command(name = "sigstrike")]
#[command(about = "An example app with subcommands", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(
        long,
        default_value = "error",
        help = "Logging level (trace, debug, info, warn, error)",
        global = true
    )]
    logging_level: String,
}

#[derive(Subcommand)]
enum Commands {
    Process {
        #[arg(long, help = "Input path to a file or directory containing Cobalt Strike beacons.")]
        input_path: PathBuf,

        #[arg(
            long,
            help = "Output path for results. If not specified, results will be printed to stdout."
        )]
        output_path: Option<PathBuf>,

    },
    Crawl {
        #[arg(long, help = "Path to input file containing URLs")]
        input_path: PathBuf,

        #[arg(long, help = "Path to output file (JSONL format)")]
        output_path: PathBuf,

        #[arg(long, default_value_t = 100)]
        max_concurrent: usize,

        #[arg(
            long,
            default_value_t = 2,
            help = "Maximum number of retries for each URL"
        )]
        max_retries: usize,

        #[arg(
            long,
            default_value_t = 10,
            help = "Timeout in seconds for each request"
        )]
        timeout: u64,
    },
}


pub fn parse_beacons(input_path: PathBuf, output_path: Option<PathBuf>) {
    let input_str_path = input_path.display().to_string();


    if input_path.is_file() {
        let files: Vec<String> = Vec::from([input_str_path.clone()]);
        if let Err(e) = process_files(files, output_path) {
            error!("Error processing file {}: {}", &input_str_path, e);
        }
    } else if input_path.is_dir() {
        let files = list_files(&input_str_path);
        info!("Found {} files in directory: {}", files.len(), &input_str_path);
        if files.is_empty() {
            error!("No files found in directory: {input_str_path}");
        }
        if let Err(e) = process_files(files, output_path) {
            error!("Error processing files in directory {}: {}", &input_str_path, e);
        }
    } else {
        error!("Input path is neither a file nor a directory: {}", &input_str_path);
    };
}

pub async fn run_cli(start_arg: usize) {
    let start = Instant::now();
    let cli = Cli::parse_from(std::env::args().skip(start_arg));

    let env = Env::default().default_filter_or(cli.logging_level);
    env_logger::Builder::from_env(env).init();


    match cli.command {
        Commands::Process {
            input_path,
            output_path,
        } => {
            parse_beacons(
                input_path,
                output_path,
            );
        }
        Commands::Crawl {
            input_path,
            output_path,
            max_concurrent,
            max_retries,
            timeout
        } => {
            let crawl_result = crate::crawler::crawl(&input_path, &output_path, max_concurrent, max_retries, timeout).await;
            if let Err(e) = crawl_result {
                error!("Error running crawler: {e}");
            }
        }
    }

    let end = Instant::now();
    let duration = end.duration_since(start);
    info!("Total execution time: {duration:?}");
}
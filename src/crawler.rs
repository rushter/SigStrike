use crate::datamodel::ParsedBeacon;
use crate::extract_beacon;
use crate::utils::generate_checksum;
use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use std::error::Error;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::{
    fs::{File, OpenOptions},
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::{mpsc, Semaphore},
    task::JoinHandle,
};
use url::Url;

// Maximum response size allowed (1MB)
const MAX_RESPONSE_SIZE: u64 = 1024 * 1024;
const MAX_REDIRECTS: usize = 3;
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36";

#[derive(Serialize)]
struct CrawlResult {
    url: String,
    status: u16,
    content_type: Option<String>,
    beacon: Option<ParsedBeacon>,
}

#[derive(Clone)]
struct ProgressTracking {
    total_count: Arc<AtomicUsize>,
    found_count: Arc<AtomicUsize>,
    failed_count: Arc<AtomicUsize>,
    non_matching_count: Arc<AtomicUsize>,
    progress_bar: ProgressBar,
}

struct CrawlConfig {
    client: Arc<Client>,
    semaphore: Arc<Semaphore>,
    max_retries: usize,
}

pub async fn crawl(
    input_path: &PathBuf,
    output_path: &PathBuf,
    max_concurrent: usize,
    max_retries: usize,
    timeout: u64,
) -> io::Result<()> {
    let config = setup_crawl_config(max_concurrent, max_retries, timeout);

    let total_lines = count_lines_in_file(input_path).await?;
    let progress = setup_progress_tracking(total_lines);
    let output_writer = setup_output_writer(output_path).await?;

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
    let progress_handle = spawn_progress_updater(progress.clone(), shutdown_rx);

    let buffer_size = (max_concurrent * 4).min(10_000);
    let (tx, rx) = mpsc::channel::<String>(buffer_size);

    let producer_handle = spawn_url_producer(input_path, tx).await?;

    process_urls(rx, config, output_writer, progress.clone(), max_concurrent).await;

    producer_handle.await?;
    let _ = shutdown_tx.send(()).await;
    let _ = progress_handle.await;

    finalize_progress_and_print_summary(progress);

    Ok(())
}

fn setup_crawl_config(max_concurrent: usize, max_retries: usize, timeout: u64) -> CrawlConfig {
    let client = Arc::new(
        Client::builder()
            .timeout(Duration::from_secs(timeout))
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .http2_keep_alive_while_idle(false)
            .pool_max_idle_per_host(0)
            .tcp_keepalive(None)
            .pool_idle_timeout(Duration::from_secs(0))
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            .user_agent(USER_AGENT)
            .build()
            .unwrap(),
    );
    let semaphore = Arc::new(Semaphore::new(max_concurrent));

    CrawlConfig {
        client,
        semaphore,
        max_retries,
    }
}

fn setup_progress_tracking(total_lines: usize) -> ProgressTracking {
    let total_count = Arc::new(AtomicUsize::new(total_lines));
    let found_count = Arc::new(AtomicUsize::new(0));
    let failed_count = Arc::new(AtomicUsize::new(0));
    let non_matching_count = Arc::new(AtomicUsize::new(0));

    let progress_bar = ProgressBar::new(total_lines as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n[{wide_bar:.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("##-"),
    );
    progress_bar.set_message("Processing URLs - Found: 0, Failed: 0, Non-matching: 0");

    ProgressTracking {
        total_count,
        found_count,
        failed_count,
        non_matching_count,
        progress_bar,
    }
}

async fn setup_output_writer(output_path: &PathBuf) -> io::Result<Arc<tokio::sync::Mutex<File>>> {
    let output = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)
        .await?;

    Ok(Arc::new(tokio::sync::Mutex::new(output)))
}

fn spawn_progress_updater(
    progress: ProgressTracking,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    update_progress_bars(&progress);
                }
                _ = shutdown_rx.recv() => {
                    update_progress_bars(&progress);
                    break;
                }
            }
        }
    })
}

fn update_progress_bars(progress: &ProgressTracking) {
    let found = progress.found_count.load(Ordering::Relaxed);
    let failed = progress.failed_count.load(Ordering::Relaxed);
    let non_matching = progress.non_matching_count.load(Ordering::Relaxed);

    let total_processed = found + failed;
    progress.progress_bar.set_position(total_processed as u64);

    let unreachable = failed.saturating_sub(non_matching);
    progress.progress_bar.set_message(format!(
        "Processing URLs - Found: {found}, Failed: {failed}, Non-matching: {non_matching}, Unreachable: {unreachable}"
    ));
}

async fn spawn_url_producer(
    input_path: &PathBuf,
    tx: mpsc::Sender<String>,
) -> io::Result<JoinHandle<()>> {
    let input = File::open(input_path).await?;
    let reader = BufReader::new(input);
    let mut lines = reader.lines();

    let handle = tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            match Url::parse(&line) {
                Ok(mut url) => {
                    // x86 checksum
                    // let checksum = generate_checksum(92);
                    // url.set_path(&checksum);
                    // let url_to_send = url.to_string();
                    // if tx.send(url_to_send.clone()).await.is_err() {
                    //     break;
                    // }
                    // x64 checksum
                    let checksum = generate_checksum(93);
                    url.set_path(&checksum);
                    let url_to_send = url.to_string();
                    if tx.send(url_to_send).await.is_err() {
                        error!("Failed to send URL: {line}");
                        break;
                    }
                }
                Err(_) => {
                    if tx.send(line.clone()).await.is_err() {
                        error!("Failed to parse URL: {line}");
                        break;
                    }
                }
            };
        }
    });

    Ok(handle)
}

async fn process_urls(
    mut rx: mpsc::Receiver<String>,
    config: CrawlConfig,
    output_writer: Arc<tokio::sync::Mutex<File>>,
    progress: ProgressTracking,
    max_concurrent: usize,
) {
    let mut tasks = FuturesUnordered::new();

    while let Some(url) = rx.recv().await {
        let permit = config.semaphore.clone().acquire_owned().await.unwrap();
        let client = config.client.clone();
        let output = output_writer.clone();
        let progress_clone = progress.clone();
        let max_retries = config.max_retries;

        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            process_single_url(&client, &url, max_retries, output, progress_clone).await;
        }));

        if tasks.len() >= max_concurrent {
            tasks.next().await;
        }
    }

    while tasks.next().await.is_some() {}
}

async fn process_single_url(
    client: &Client,
    url: &str,
    max_retries: usize,
    output: Arc<tokio::sync::Mutex<File>>,
    progress: ProgressTracking,
) {
    let result = fetch_and_process(client, url, max_retries, &progress.non_matching_count).await;

    let result = match result {
        Some(r) if r.beacon.is_some() => r,
        _ => {
            progress.failed_count.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    if let Ok(json) = serde_json::to_string(&result) {
        let mut out = output.lock().await;
        let _ = out.write_all(json.as_bytes()).await;
        let _ = out.write_all(b"\n").await;
        progress.found_count.fetch_add(1, Ordering::Relaxed);
    } else {
        progress.failed_count.fetch_add(1, Ordering::Relaxed);
    }
}

async fn count_lines_in_file(path: &PathBuf) -> io::Result<usize> {
    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let mut count = 0;

    while lines.next_line().await?.is_some() {
        count += 1;
    }

    Ok(count)
}

fn finalize_progress_and_print_summary(progress: ProgressTracking) {
    let found = progress.found_count.load(Ordering::Relaxed);
    let failed = progress.failed_count.load(Ordering::Relaxed);
    let non_matching = progress.non_matching_count.load(Ordering::Relaxed);
    let unreachable = failed.saturating_sub(non_matching);

    progress.progress_bar.set_message(format!(
        "Completed - Found: {found}, Failed: {failed}, Non-matching: {non_matching}, Unreachable: {unreachable}"
    ));
    progress.progress_bar.finish();

    info!("\nCrawl Summary:");
    info!(
        "  Total URLs processed: {}",
        progress.total_count.load(Ordering::Relaxed)
    );
    info!("  Found: {found}");
    info!("  Failed: {failed}");
    info!("  Non-matching content type/status: {non_matching}");
    info!("  Unreachable: {unreachable}");
}

async fn fetch_and_process(
    client: &Client,
    url: &str,
    max_retries: usize,
    non_matching_count: &Arc<AtomicUsize>,
) -> Option<CrawlResult> {
    let mut retry_count = 0;

    'retries: loop {
        match client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|ct| ct.to_str().ok())
                    .map(String::from);

                if status != StatusCode::OK {
                    // We could also check for content type, but some endpoints return application/json instead
                    // of application/octet-stream.
                    non_matching_count.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                // check content length before reading
                if resp
                    .headers()
                    .get("content-length")
                    .and_then(|val| val.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .filter(|&length| length > MAX_RESPONSE_SIZE)
                    .is_some()
                {
                    error!("Response too large for {url}");
                    return None;
                }

                // Read response in chunks with size limit
                return match read_response_with_limit(resp).await {
                    Ok(bytes) => {
                        let result =
                            tokio::task::spawn_blocking(move || _perform_extraction(&bytes))
                                .await
                                .unwrap();
                        if let Ok(result) = result {
                            Some(CrawlResult {
                                url: url.to_string(),
                                status: status.as_u16(),
                                content_type,
                                beacon: Some(result),
                            })
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        debug!("Error reading response for {url}: {e}");
                        if retry_count < max_retries {
                            retry_count += 1;
                            let delay = Duration::from_millis(100 * (1 << retry_count.min(10)));
                            tokio::time::sleep(delay).await;
                            continue 'retries;
                        }
                        None
                    }
                };
            }
            Err(e) => {
                debug!("Error fetching {url}: {e}");
                if retry_count < max_retries && is_retryable_error(&e) {
                    retry_count += 1;
                    let delay = Duration::from_millis(100 * (1 << retry_count.min(10)));
                    tokio::time::sleep(delay).await;
                    continue 'retries;
                }
                return None;
            }
        }
    }
}

fn is_retryable_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_request()
}

async fn read_response_with_limit(
    response: reqwest::Response,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut buffer = Vec::new();
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;

        if buffer.len() + chunk.len() > MAX_RESPONSE_SIZE as usize {
            debug!("Response size exceeds maximum allowed size");
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "Response size exceeds maximum allowed size",
            )));
        }

        buffer.extend_from_slice(&chunk);
    }

    Ok(buffer)
}

fn _perform_extraction(data: &[u8]) -> Result<ParsedBeacon, String> {
    let result = extract_beacon(data);
    match result {
        Ok(parsed_beacon) => Ok(parsed_beacon),
        Err(e) => Err(e.to_string()),
    }
}

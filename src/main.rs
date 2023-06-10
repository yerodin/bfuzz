extern crate clap;
use clap::ValueHint;
use clap::{arg, value_parser, Arg, ArgAction};
use colored::Colorize;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use indicatif::MultiProgress;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use regex::Regex;
use std::error::Error;
use std::fmt;
use std::io::ErrorKind;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio::time::Duration;

#[derive(Debug)]
struct ScanError {
    kind: ErrorKind,
    payload: String,
    message: String,
}

impl ScanError {
    fn new(k: ErrorKind, msg: &str, payload: &str) -> ScanError {
        ScanError {
            kind: k,
            message: msg.to_string(),
            payload: payload.to_string(),
        }
    }
    fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for ScanError {
    fn description(&self) -> &str {
        &self.message
    }
}

async fn escape_ignores(mut ignore_values: Vec<&String>) -> Vec<String> {
    let mut new_values: Vec<String> = Vec::new();
    for ele in ignore_values.iter_mut() {
        new_values.push(escape_ignore(ele.to_string()));
    }
    return new_values;
}

async fn escape_regex_ignores(mut ignore_values: Vec<&String>) -> Vec<Regex> {
    let mut new_values: Vec<Regex> = Vec::new();
    for ele in ignore_values.iter_mut() {
        new_values.push(Regex::new(&escape_ignore(ele.to_string())).unwrap());
    }
    return new_values;
}

fn escape_ignore(s: String) -> String {
    let mut n = s.replace("\\n", "\n");
    n = n.replace("\\r", "\r");
    n = n.replace("\\t", "\t");
    n = n.replace("\\'", "\'");
    return n;
}

async fn scan_addr(
    addr: &str,
    fuzz_data: String,
    new_lines: bool,
    retries: u32,
    timeout: &u32,
) -> Result<(String, String), ScanError> {
    let mut err: ScanError = ScanError::new(std::io::ErrorKind::Other, "", &fuzz_data);
    for _ in 0..retries {
        let mut stream: TcpStream;
        match TcpStream::connect(addr).await {
            Ok(s) => {
                stream = s;
                sleep(Duration::from_millis(100)).await;
            }
            Err(e) => {
                err = ScanError::new(e.kind(), &e.to_string(), &fuzz_data);
                continue;
            }
        };
        let mut fuzz_string = fuzz_data.to_string();
        if new_lines {
            fuzz_string = fuzz_string + "\n";
        }
        let data = fuzz_string.as_bytes();
        match stream.write_all(data).await {
            Ok(_) => {}
            Err(e) => {
                err = ScanError::new(e.kind(), &e.to_string(), &fuzz_data);
                continue;
            }
        };
        let mut received = Vec::new();
        let mut buf = [0; 4096];
        let mut timedout = false;
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(*timeout as u64),
                stream.read(&mut buf),
            )
            .await
            {
                Ok(n) => {
                    // stream.close().await;
                    if n.is_err() {
                        let e = n.err().unwrap();
                        err = ScanError::new(e.kind(), &e.to_string(), &fuzz_data);
                    } else {
                        let val = n.ok().unwrap();
                        if val == 0 {
                            break;
                        } else {
                            received.extend_from_slice(&buf[0..val]);
                        }
                    }
                }
                Err(e) => {
                    err = ScanError::new(ErrorKind::TimedOut, &e.to_string(), &fuzz_data);
                    sleep(Duration::from_millis(100)).await;
                    timedout = true;
                    break;
                }
            };
        }
        if timedout {
            continue;
        }
        return Ok((fuzz_data, String::from_utf8(received).unwrap().to_string()));
    }
    Err(err)
}

async fn fuzz(
    wordlist: &str,
    target: &String,
    port: &u16,
    batch_size: &u16,
    new_lines: bool,
    ignore_values: Vec<String>,
    ignore_regex_values: Vec<Regex>,
    timeout: &u32,
) {
    let wordlist_info = get_wordlist_info(wordlist)
        .await
        .expect("error getting wordlist info");
    let count_lines = wordlist_info.0;
    let max_length = wordlist_info.1;
    let mb = MultiProgress::new();

    let pb_style = ProgressStyle::with_template("\n{prefix}{wide_bar} {pos}/{len}").unwrap();
    let pb = mb.add(ProgressBar::new(count_lines).with_style(pb_style));
    let status_style = ProgressStyle::with_template("{msg}")
        .unwrap()
        .tick_chars("-/+\\");
    let sb = mb.add(ProgressBar::new(count_lines).with_style(status_style.clone()));
    sb.set_message(format!(
        "Timeouts: {}      Errors: {}",
        "0".yellow(),
        "0".red()
    ));
    let sock_addr: &str = &(target.to_string() + ":" + &port.to_string());
    let mut timeouts: u64 = 0;
    let mut errors: u64 = 0;

    let mut lines = BufReader::new(File::open(wordlist).await.unwrap()).lines();
    let mut async_futures = FuturesUnordered::new();
    let mut done: i64 = 0;
    pb.println(format!("Target          : {}", sock_addr.yellow()));
    pb.println(format!(
        "Wordlist Size   : {}",
        count_lines.to_string().yellow()
    ));
    pb.println(format!(
        "Batch Size      : {}",
        batch_size.to_string().yellow()
    ));
    pb.println(format!(
        "Timeout         : {}{}",
        timeout.to_string().yellow(),
        "ms".yellow()
    ));
    pb.println("-------------------------------");
    pb.println("\n ");

    for _ in 0..*batch_size {
        if let Some(line) = lines.next_line().await.unwrap() {
            let s = scan_addr(sock_addr, line, new_lines, 3, timeout);
            async_futures.push(s);
        } else {
            break;
        }
    }

    while let Some(result) = async_futures.next().await {
        if let Some(line) = lines.next_line().await.unwrap() {
            async_futures.push(scan_addr(sock_addr, line, new_lines, 3, timeout));
        }
        match result {
            Ok(response) => {
                done = done + 1;
                pb.inc(1);
                if !ignore_values.iter().any(|s| s.eq(&response.1))
                    && !ignore_regex_values.iter().any(|r| r.is_match(&response.1))
                {
                    let output_params = gen_output_params(response.0, &max_length, false).await;

                    pb.println(format!(
                        "[{}]    {}{}Response: [{}]",
                        "+".green(),
                        escape_for_print(output_params.0),
                        output_params.1,
                        escape_for_print(response.1).blue()
                    ));
                }
            }
            Err(e) => {
                done = done + 1;
                pb.inc(1);
                if e.kind().eq(&tokio::io::ErrorKind::TimedOut) {
                    timeouts = timeouts + 1;
                    // pb.println(format!("[{}] Payload: [{}]","TIMEOUT".bright_yellow(), e.to_string()));
                } else {
                    errors = errors + 1;
                    let output_params = gen_output_params(e.payload, &max_length, true).await;
                    pb.println(format!(
                        "[{}]    {}{}Error: [{}]",
                        "!".red(),
                        escape_for_print(output_params.0),
                        output_params.1,
                        e.message.red()
                    ));
                    // pb.println(format!("[{}] Payload: [{}]", "ERROR".red(), e.to_string()));
                    // pb.println(format!("{}","Maybe the server cannot handle this amount of requests. Try with smaller batch size --batch-size SIZE".red()));
                }
            }
        }
        sb.set_message(format!(
            "Timeouts: {}      Errors: {}",
            timeouts.to_string().yellow(),
            errors.to_string().red()
        ));
    }
    pb.finish();
    println!("\n ");
    pb.finish_and_clear();
    println!(
        "{}{}{}",
        "[".green().on_green(),
        "DONE!".black().on_green(),
        "]".green().on_green()
    );
}

async fn gen_output_params(payload: String, max_len: &u64, is_error: bool) -> (String, String) {
    let p;
    if is_error {
        p = payload.red();
    } else {
        p = payload.green();
    }
    let payload_string = format!("Payload:[{}]", p);
    let mut l = *max_len as i64;
    if l > 40 {
        l = 40;
    }
    let mut filler_count: i64 = l - payload_string.len() as i64;
    if filler_count < 0 {
        filler_count = 0;
    }
    let filler_string = " ".repeat(filler_count as usize);
    return (payload_string, filler_string);
}

async fn get_wordlist_info(file: &str) -> std::io::Result<(u64, u64)> {
    let mut count = 0u64;
    let mut max_length = 0u64;
    let mut lines = BufReader::new(File::open(file).await?).lines();
    while let Some(line) = lines.next_line().await? {
        let size = line.len();
        count += 1;
        if size > max_length.try_into().unwrap() {
            max_length = max_length + 1;
        }
    }
    Ok((count, max_length))
}

fn escape_for_print(s: String) -> String {
    return s.replace("\n", "\\n").replace("\r", "\\r");
}

#[tokio::main]
async fn main() {
    let banner = r#" _       ___                   
| |     / __)            v0.1.1
| |__ _| |__ _   _ _____ _____ 
|  _ (_   __) | | (___  |___  )
| |_) )| |  | |_| |/ __/ / __/ 
|____/ |_|  |____/(_____|_____)"#;
    let banner_text = "Blazing Fast Basic Port Fuzzer".on_blue();
    let mut cmd = clap::Command::new("bfuzz").bin_name("bfuzz");

    cmd = cmd.arg(
        arg!(-w --wordlist <WORDLIST> "Specify the wordlist")
            .required(true)
            .value_hint(ValueHint::FilePath)
            .value_parser(value_parser!(PathBuf)),
    );
    cmd = cmd.arg(arg!(-t --target <TARGET> "The host to fuzz").required(true));
    cmd = cmd.arg(
        arg!(-p --port <PORT> "The port to fuzz")
            .required(true)
            .value_parser(value_parser!(u16)),
    );
    cmd = cmd.arg(
        Arg::new("batch-size")
            .long("batch-size")
            .short('b')
            .help("Request Batch size")
            .value_name("SIZE")
            .default_value("1000")
            .value_parser(value_parser!(u16)),
    );

    cmd = cmd.arg(
        Arg::new("timeout")
            .long("timeout")
            .short('T')
            .help("How long to wait for responses in milliseconds")
            .value_name("MS")
            .default_value("250")
            .value_parser(value_parser!(u32)),
    );

    // cmd = cmd.arg(arg!(-U --udp "Fuzz over UDP").action(ArgAction::SetTrue));
    cmd = cmd.arg(
        Arg::new("ignore")
            .long("ignore")
            .short('i')
            .help("Ignores responses with the specific value")
            .value_name("RESPONSE")
            .action(ArgAction::Append),
    );
    cmd = cmd.arg(
        Arg::new("ignore-regex")
            .long("ignore-regex")
            .short('I')
            .help("Ignores responses matching the specific regex")
            .value_name("REGEX")
            .action(ArgAction::Append),
    );
    cmd = cmd.arg(
        Arg::new("no-newline")
            .long("no-newline")
            .short('n')
            .help("Do not fuzz with trailing new line")
            .action(ArgAction::SetTrue),
    );
    let matches = cmd.get_matches();

    let wordlist_path = matches.get_one::<PathBuf>("wordlist").expect("required");
    let wordlist = wordlist_path.to_str().unwrap();
    let target = matches.get_one::<String>("target").expect("required");
    let port = matches.get_one::<u16>("port").expect("required");
    let batch_size = matches.get_one::<u16>("batch-size").unwrap();
    let timeout = matches.get_one::<u32>("timeout").expect("required");
    // let udp = matches.get_flag("udp");
    let no_new_lines = matches.get_flag("no-newline");
    let ignore_matches = matches.get_many::<String>("ignore");
    let ignore_regex_matches = matches.get_many::<String>("ignore-regex");
    let mut ignore_values: Vec<String> = Vec::new();
    if !ignore_matches.is_none() {
        ignore_values = escape_ignores(ignore_matches.unwrap().collect::<Vec<_>>()).await;
    }

    let mut ignore_regex_values: Vec<Regex> = Vec::new();
    if !ignore_regex_matches.is_none() {
        ignore_regex_values =
            escape_regex_ignores(ignore_regex_matches.unwrap().collect::<Vec<_>>()).await;
    }
    println!("{}\n{}\n", banner.blue(), banner_text);
    fuzz(
        &wordlist,
        target,
        port,
        batch_size,
        !no_new_lines,
        ignore_values,
        ignore_regex_values,
        timeout,
    )
    .await;
}

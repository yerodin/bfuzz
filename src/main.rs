extern crate clap;
use async_std::fs::File;
use async_std::io::prelude::SeekExt;
use async_std::io::{prelude::BufReadExt, ReadExt};
use async_std::io::{BufReader, SeekFrom};
use async_std::stream::StreamExt;
use async_std::{
    io,
    net::{TcpStream, ToSocketAddrs},
    task,
};
use clap::{arg, value_parser, Arg, ArgAction};
use futures::stream::FuturesUnordered;
use futures::AsyncWriteExt;
use std::fmt::format;
use std::path::PathBuf;
use indicatif::{ProgressBar, ProgressStyle};
use colored::Colorize;

async fn escape_ignores(mut ignore_values: Vec<&String>) -> Vec<String> {
    let mut new_values: Vec<String> = Vec::new();
    for ele in ignore_values.iter_mut() {
        let mut n = ele.replace("\\n", "\n");
        n = n.replace("\\r", "\r");
        n = n.replace("\\t", "\t");
        n = n.replace("\\'", "\'");
        new_values.push(n);
    }
    return new_values;
}

async fn scan_addr(
    addr: impl ToSocketAddrs,
    fuzz_data: String,
    new_lines: bool,
    retries: u32,
) -> io::Result<(String, String)> {
    let mut err: std::io::Error = std::io::Error::new(std::io::ErrorKind::Other, "");
    for _ in 0..retries {
        let mut stream = TcpStream::connect(&addr).await.expect("Could Not Connect");
        let mut fuzz_string = fuzz_data.to_string();
        if new_lines {
            fuzz_string = fuzz_string + "\n";
        }
        let data = fuzz_string.as_bytes();
        match stream.write_all(data).await {
            Ok(_) => {}
            Err(e) => {
                err = e;
            }
        };
        let mut buf = vec![0u8; 1024];
        match stream.read(&mut buf).await {
            Ok(n) => {
                stream.close().await;
                return Ok((fuzz_data, String::from_utf8_lossy(&buf[..n]).to_string()))},
            Err(e) => {
                err = e;
            }
        };
    }
    Err(err)
}

async fn fuzz(
    wordlist: &File,
    target: &String,
    port: &u16,
    batch_size: &u16,
    new_lines: bool,
    ignore_values: Vec<String>,
) {
    let wordlist_info = get_wordlist_info(wordlist).await.expect("error getting wordlist info");
    let count_lines = wordlist_info.0;
    let max_length = wordlist_info.1;
    let pb = ProgressBar::new(count_lines);
    let addr: String = target.to_string() + ":" + &port.to_string();
    
    let sock_addr = addr
        .to_socket_addrs()
        .await
        .expect("Error convert sock addr")
        .next()
        .unwrap();
    let mut lines = BufReader::new(wordlist).lines();
    let mut async_futures = FuturesUnordered::new();
    let mut done: i64 = 0;

    pb.println(format!("Target          : {}", addr.green().yellow()));
    pb.println(format!("Wordlist Size   : {}", count_lines.to_string().yellow()));
    pb.println(format!("Batch Size      : {}\n\n", batch_size.to_string().yellow()));
    for _ in 0..*batch_size {
        if let Some(line) = lines.next().await {
            let s = scan_addr(
                sock_addr,
                line.expect("Error reading wordlist entry"),
                new_lines,
                3,
            );
            async_futures.push(s);
        } else {
            break;
        }
    }

    while let Some(result) = async_futures.next().await {
        if let Some(line) = lines.next().await {
            
            async_futures.push(scan_addr(sock_addr, line.expect(""), new_lines, 3));
        }
        match result {
            Ok(response) => {
                done = done + 1;
                pb.inc(1);
                if !ignore_values.iter().any(|s| s.eq(&response.1)) {
                    let payload_string = format!("Payload:[{}]", response.0.green());
                    let mut l = max_length as i64;
                    if l > 40 {
                        l = 40;
                    }
                    let mut filler_count: i64 = l - payload_string.len() as i64;
                    if filler_count < 0 {
                        filler_count = 0;
                    }
                    let filler_string = " ".repeat(filler_count as usize);
                    pb.println(format!("[{}]: {}{}Response: [{}]","Found!".green(),payload_string, filler_string, response.1.replace("\n", "\\n").blue()));
                }
            }
            Err(e) => {
                pb.println(format!("[{}] Payload: [{}]","ERROR".red(), e.to_string()));
                pb.println(format!("{}","Maybe the server cannot handle this amount of requests. Try with smaller batch size --batch-size SIZE".red()));
            }
        }
    }
    pb.finish_with_message("done");
    println!("\n\n[{}]", "DONE!".bright_green());
}

async fn get_wordlist_info(mut file: &File) -> std::io::Result<(u64,u64)> {
    let mut count = 0u64;
    let mut max_length = 0u64;
    task::block_on(async {
        let mut lines = BufReader::new(file).lines();
        while let Some(line) = lines.next().await {
            let size = line?.len();
            count += 1;
            if size > max_length.try_into().unwrap() {
                max_length = max_length + 1;
            }
        }
        file.seek(SeekFrom::Start(0)).await?;
        Ok((count, max_length))
    })
}

#[async_std::main]
async fn main() -> io::Result<()> {
    let banner = r#" _       ___                   
| |     / __)            v0.1      
| |__ _| |__ _   _ _____ _____ 
|  _ (_   __) | | (___  |___  )
| |_) )| |  | |_| |/ __/ / __/ 
|____/ |_|  |____/(_____|_____)
Blazing Fast Basic Port Fuzzer"#;
    let mut cmd = clap::Command::new("bfuzz").bin_name("bfuzz");
    cmd = cmd.arg(
        arg!(-w --wordlist <WORDLIST> "Specify the wordlist")
            .required(true)
            .value_parser(value_parser!(PathBuf)),
    );
    cmd = cmd.arg(arg!(-t --target <TARGET> "The host to fuzz").required(true));
    cmd = cmd.arg(
        arg!(-p --port <PORT> "The port to fuzz")
            .required(true)
            .value_parser(value_parser!(u16))
    );
    cmd = cmd.arg(
        Arg::new("batch-size")
            .long("batch-size")
            .short('b')
            .help("Request Batch size")
            .value_name("SIZE")
            .default_value("1000")
            .value_parser(value_parser!(u16))
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
    // cmd = cmd.arg(arg!(-i --ignore <RESPONSE> "Ignores responses with the specific value").action(ArgAction::Append));
    cmd = cmd.arg(
        Arg::new("no-newline")
            .long("no-newline")
            .short('n')
            .help("Do not fuzz with trailing new line")
            .action(ArgAction::SetTrue),
    );
    let matches = cmd.get_matches();

    let wordlist_path = matches.get_one::<PathBuf>("wordlist").expect("required");
    let wordlist = File::open(wordlist_path).await.expect(
        &("Could not read wordlist file at ".to_owned()
            + &wordlist_path.as_path().display().to_string()),
    );
    let target = matches.get_one::<String>("target").expect("required");
    let port = matches.get_one::<u16>("port").expect("required");
    let batch_size = matches.get_one::<u16>("batch-size").unwrap();
    // let udp = matches.get_flag("udp");
    let no_new_lines = matches.get_flag("no-newline");
    let ignore_matches = matches.get_many::<String>("ignore");
    let mut ignore_values: Vec<String> = Vec::new();
    if !ignore_matches.is_none() {
        ignore_values = escape_ignores(ignore_matches.unwrap().collect::<Vec<_>>()).await;
    }
    println!("{}\n", banner.blue());
    task::block_on(fuzz(
        &wordlist,
        target,
        port,
        batch_size,
        !no_new_lines,
        ignore_values,
    ));
    Ok(())
}

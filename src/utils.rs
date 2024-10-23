use std::{collections::HashMap, str::FromStr};

use regex::Regex;
use solana_sdk::pubkey::Pubkey;
use tokio::{fs::File, io::{AsyncBufReadExt, BufReader}};

pub fn get_data_from_logs_by_regex(logs: &Vec<String>, regex: &str) -> Option<String> {
    let regex = Regex::new(regex).unwrap();

    let mut data: Option<String> = None;

    for log in logs {
        if let Some(captures) = regex.captures(log) {
            if let Some(str) = captures.get(1) {
                data = Some(str.as_str().to_string());
                break;
            }
        }
    }

    data
}

pub async fn read_mints_or_deployers_from_file(filename: &str, file_type: &str, initial: bool) -> Result<Vec<(String, f64, f64, f64)>, std::io::Error> {
    let file = File::open(filename).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let mut data = Vec::new();

    while let Some(line) = lines.next_line().await? {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() == 4 {
            let address = parts[0].to_owned();
            let snipe_height = parts[1].parse::<f64>().expect(&format!("{} > Invalid snipe height on address {}", file_type, address));
            let jito_tip = parts[2].parse::<f64>().expect(&format!("{} > Invalid jito tip on address {}", file_type, address));
            let slippage = parts[3].parse::<f64>().expect(&format!("{} > Invalid slippage on address {}", file_type, address));

            if Pubkey::from_str(&address).is_err() {
                log_with_panic(format!("{} > Invalid address {}", file_type, address), initial);
            }

            if snipe_height <= 0.0 {
                log_with_panic(format!("{} > Invalid snipe height {}. Snipe height must be greater than 0 on address {}", file_type, snipe_height, address), initial);
            }

            if jito_tip <= 0.0 {
                log_with_panic(format!("{} > Invalid jito tip {}. Jito tip must be greater than 0 on address {}", file_type, jito_tip, address), initial);
            }

            if slippage < 0.0 || slippage > 100.0 {
                log_with_panic(format!("{} > Invalid slippage {}. Slippage must be between 0 and 100 on address {}", file_type, slippage, address), initial);
            }

            data.push((address, snipe_height, jito_tip, slippage));
        } else {
            log_with_panic(format!("Each {} element must be formatted as 'address|snipe height|jito tip|slippage' for line '{}'", file_type, line), initial);
        }
    }

    for (address, _snipe_height, _jito_tip, _slippage) in &data {
        if data.iter().filter(|(a, _snipe_height, _jito_tip, _slippage)| a == address).count() > 1 {
            log_with_panic(format!("{} > Same address used multiple times {}", file_type, address), initial);
        }
    }

    Ok(data)
}

pub fn report_changes(old_data: &[(String, f64, f64, f64)], new_data: &[(String, f64, f64, f64)], config_name: &str, initial: bool) {
    if initial {
        return;
    }

    let old_map: HashMap<String, (f64, f64, f64)> = old_data.iter().map(|x| (x.0.clone(), (x.1, x.2, x.3))).collect();
    let new_map: HashMap<String, (f64, f64, f64)> = new_data.iter().map(|x| (x.0.clone(), (x.1, x.2, x.3))).collect();

    for (new_key, new_value) in &new_map {
        match old_map.get(new_key) {
            Some(old_value) if old_value != new_value => {
                let (old_snipe_height, old_jito_tip, old_slippage) = old_value;
                let (new_snipe_height, new_jito_tip, new_slippage) = new_value;

                log::info!("{} > Updated - {} \n\t\tOld > Snipe height: {} SOL, Jito tip: {} SOL, Slippage: {} % \n\t\tNew > Snipe height: {} SOL, Jito tip: {} SOL, Slippage: {} %", config_name, new_key, old_snipe_height, old_jito_tip, old_slippage, new_snipe_height, new_jito_tip, new_slippage);
            },
            None => {
                let (new_snipe_height, new_jito_tip, new_slippage) = new_value;

                log::info!("{} > Added - {} \n\t\tValue > Snipe height: {} SOL, Jito tip: {} SOL, Slippage: {} %", config_name, new_key, new_snipe_height, new_jito_tip, new_slippage);
            },
            _ => {}
        }
    }

    for old_key in old_map.keys() {
        if !new_map.contains_key(old_key) {
            log::info!("{} > Removed - {}", config_name, old_key);
        }
    }

    if old_map == new_map {
        log::info!("{}: No changes detected.", config_name);
    }
}

pub fn log_with_panic(message: String, initial: bool) {
    log::error!("{}", message);

    if initial {
        std::process::exit(1);
    }
}

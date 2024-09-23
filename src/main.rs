mod raydium;
mod utils;

use chrono::{Local, TimeZone};
use colored::Colorize;
use solana_account_decoder::UiAccountEncoding;
use solana_sdk::{commitment_config::CommitmentConfig, compute_budget::ComputeBudgetInstruction, instruction::{AccountMeta, Instruction}, native_token::{lamports_to_sol, sol_to_lamports}, pubkey::Pubkey, signature::{Keypair, Signature}, signer::Signer, system_instruction::transfer, transaction::Transaction};
use solana_client::{nonblocking::rpc_client::RpcClient, rpc_config::{RpcAccountInfoConfig, RpcSendTransactionConfig, RpcTransactionConfig, RpcTransactionLogsConfig, RpcTransactionLogsFilter}};
use solana_transaction_status::{EncodedTransaction, UiInstruction, UiMessage, UiParsedInstruction, UiTransactionEncoding};
use spl_associated_token_account::{get_associated_token_address, get_associated_token_address_with_program_id, instruction::{create_associated_token_account, create_associated_token_account_idempotent}};
use spl_token::instruction::{close_account, sync_native};
use tokio::{fs::{self, File}, io::AsyncReadExt, sync::Mutex, time};
use utils::{get_data_from_logs_by_regex, read_mints_or_deployers_from_file, report_changes};
use std::{env, str::FromStr, sync::Arc, time::Duration};
use dotenv::dotenv;
use log::{Level, LevelFilter};
use solana_client::pubsub_client::PubsubClient;
use crate::raydium::*;

const MAX_RETRIES: usize = 1_000;

#[tokio::main]
async fn main() {
    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    let level_filter = match log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    let log_dir = "log";
    fs::create_dir_all(log_dir).await.unwrap();

    fern::Dispatch::new()
        .format(move |out, message, record| {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S.%3f");

            let level = format!("[ {} ]", match record.level() {
                Level::Info => "+".green(),
                Level::Error => "-".red(),
                Level::Warn => "!".yellow(),
                Level::Debug => "*".blue(),
                Level::Trace => "~".purple(),
            });
            
            out.finish(format_args!(
                "{} {} > {}",
                timestamp,
                level,
                message
            ))
        })
        .level(level_filter)
        .chain(std::io::stdout())
        .chain(fern::log_file(format!("{}/output.ans", log_dir)).unwrap())
        .apply()
        .unwrap();

    dotenv().ok();

    log::info!("Hyper Sniper");

    let priority_fees = Arc::new(env::var("PRIORITY_FEES")
        .expect("Missing PRIORITY_FEES amount")
        .parse::<u64>()
        .expect("Invalid PRIORITY_FEES amount"));

    let mints: Arc<Mutex<Vec<(String, f64, f64, f64)>>> = Arc::new(Mutex::new(Vec::new()));
    let mints_cloned = mints.clone();
    tokio::spawn(async move {
        let mut initial = true;
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            match read_mints_or_deployers_from_file("mints.txt", "MINTS", initial).await {
                Ok(data) => {
                    let mut write_guard = mints_cloned.lock().await;

                    if write_guard.eq(&data) {
                        continue;
                    }

                    report_changes(&*write_guard, &data, "MINTS", initial);

                    *write_guard = data;

                    if initial {
                        initial = false;
                    }
                },
                Err(e) => eprintln!("Failed to read mints data: {}", e),
            }
        }
    });

    let deployers: Arc<Mutex<Vec<(String, f64, f64, f64)>>> = Arc::new(Mutex::new(Vec::new()));
    let deployers_cloned = deployers.clone();
    tokio::spawn(async move {
        let mut initial = true;
        let mut interval = time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            match read_mints_or_deployers_from_file("deployers.txt", "DEPLOYERS", initial).await {
                Ok(data) => {
                    let mut write_guard = deployers_cloned.lock().await;

                    if write_guard.eq(&data) {
                        continue;
                    }

                    report_changes(&*write_guard, &data, "DEPLOYERS", initial);

                    *write_guard = data;

                    if initial {
                        initial = false;
                    }
                },
                Err(e) => eprintln!("Failed to read deployers data: {}", e),
            }
        }
    });

    let keypair_path = env::var("KEYPAIR_PATH")
        .expect("Missing KEYPAIR_PATH");
    let mut keypair_file = File::open(keypair_path)
        .await
        .expect("Failed to open keypair file");
    let mut contents = String::new();
    keypair_file.read_to_string(&mut contents).await.unwrap();
    let keypair_bytes: Vec<u8> = serde_json::from_str(&contents).unwrap();
    let keypair = Arc::new(Keypair::from_bytes(&keypair_bytes).unwrap());

    let jito_url = Arc::new(env::var("JITO_URL")
        .expect("Missing JITO_URL"));

    let rpc_url = env::var("RPC_URL")
        .expect("Missing RPC URL or Helius API key");
    let rpc = Arc::new(RpcClient::new(rpc_url.to_string()));

    let mints_lock = mints.lock().await;

    let mints_string = mints_lock.iter()
        .map(|(address, snipe_height, jito_tip, slippage)| {
            format!("Token address > {} \n\t\t\tSnipe height: {} SOL \n\t\t\tJito tip: {} SOL \n\t\t\tSlippage: {} %", address, snipe_height, jito_tip, slippage)
        })
        .collect::<Vec<_>>()
        .join("\n\t\t");

    drop(mints_lock);

    let deployers_lock = deployers.lock().await;

    let deployers_string = deployers_lock.iter()
        .map(|(address, snipe_height, jito_tip, slippage)| {
            format!("Deployer address > {} \n\t\t\tSnipe height: {} SOL \n\t\t\tJito tip: {} SOL \n\t\t\tSlippage: {} %", address, snipe_height, jito_tip, slippage)
        })
        .collect::<Vec<_>>()
        .join("\n\t\t");

    drop(deployers_lock);

    let balance = lamports_to_sol(rpc.get_balance(&keypair.pubkey()).await.unwrap());

    log::info!("Settings: \n\tWallet: {}\n\tWallet Balance: {} SOL\n\tPRIORITY_FEES: {} µLamports\n\tMINTS:\n\t\t{}\n\tDEPLOYERS:\n\t\t{}\n\tJITO_URL: {}\n\tRPC_URL: {}\n\tWSS_URL: {}", keypair.pubkey(), balance, priority_fees, mints_string, deployers_string, jito_url, rpc_url, env::var("WSS_URL").expect("Missing websocket url or Helius API key"));
    
    loop {
        let logs_filter = RpcTransactionLogsFilter::All;
        let logs_config = RpcTransactionLogsConfig {
            commitment: Some(CommitmentConfig::confirmed())
        };

        let ws = PubsubClient::logs_subscribe(
            &env::var("WSS_URL")
                .expect("Missing websocket url or Helius API key"), logs_filter, logs_config)
            .unwrap();

        log::info!("Listening for tokens...");

        while let Ok(response) = ws.1.recv_timeout(Duration::from_secs(30)) {
            let jito_url = Arc::clone(&jito_url);
            let priority_fees = Arc::clone(&priority_fees);
            let mints = Arc::clone(&mints);
            let deployers = Arc::clone(&deployers);
            let rpc = Arc::clone(&rpc);
            let keypair = Arc::clone(&keypair);

            tokio::spawn(async move {
                let logs = response.value.logs.clone();

                if response.value.err.is_some() {
                    return;
                }

                let signature = Signature::from_str(&response.value.signature.as_str()).expect("Invalid signature");

                if logs.iter().any(|log| log.contains(&RAYDIUM_STANDARD_AMM_PROGRAM_ID.to_string()))
                    && !logs.iter().any(|log| 
                        log.contains(&"SwapBaseIn".to_string())
                        || log.contains(&"SwapBaseOutput".to_string())
                        || log.contains(&"CollectProtocolFee".to_string())
                        || log.contains(&"Deposit".to_string())
                        || log.contains(&"CollectFundFee".to_string())
                        || log.contains(&"Burn".to_string())
                    ) {
                    let vault_0_amount_str = get_data_from_logs_by_regex(&logs, r"vault_0_amount:(\d+),");
                    let vault_0_amount = vault_0_amount_str.unwrap().as_str().parse::<f64>().unwrap();

                    let vault_1_amount_str = get_data_from_logs_by_regex(&logs, r"vault_1_amount:(\d+)");
                    let vault_1_amount = vault_1_amount_str.unwrap().as_str().parse::<f64>().unwrap();

                    log::debug!("CPMM > vault_0_amount: {}, vault_amount_1: {}", vault_0_amount, vault_1_amount);
    
                    let mut tx_retries = 0;

                    let tx = loop {
                        match rpc.get_transaction_with_config(&signature, RpcTransactionConfig {
                            commitment: Some(CommitmentConfig::confirmed()),
                            max_supported_transaction_version: Some(0),
                            encoding: Some(UiTransactionEncoding::JsonParsed),
                        }).await {
                            Ok(tx) => break tx,
                            Err(e) => {
                                if !e.to_string().contains("invalid type: null") {
                                    log::error!("CPMM > Error getting transaction: {}", e);
                                } else {
                                    log::debug!("CPMM > Error getting transaction: {}", e);
                                }
    
                                tx_retries += 1;
    
                                if tx_retries >= MAX_RETRIES {
                                    log::error!("CPMM > Max retries reached in transaction. Exiting loop.");
                                    return;
                                }
    
                                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await
                            }
                        }
                    };

                    log::debug!("CPMM > Pool creation transaction: {:?}", tx);

                    let mut accounts: Vec<String> = vec![];

                    match tx.transaction.transaction {
                        EncodedTransaction::LegacyBinary(_) => return,
                        EncodedTransaction::Binary(_, _) => return,
                        EncodedTransaction::Json(tx) => {
                            match tx.message {
                                UiMessage::Parsed(message) => {
                                    for ix in message.instructions {
                                        match ix {
                                            UiInstruction::Compiled(_) => return,
                                            UiInstruction::Parsed(ix) => {
                                                match ix {
                                                    UiParsedInstruction::Parsed(_) => continue,
                                                    UiParsedInstruction::PartiallyDecoded(ix) => {
                                                        if ix.program_id == RAYDIUM_STANDARD_AMM_PROGRAM_ID {
                                                            accounts = ix.accounts;

                                                            break;
                                                        }
                                                    },
                                                }
                                            },
                                        }
                                    }
                                },
                                UiMessage::Raw(_) => return,
                            }
                        },
                        EncodedTransaction::Accounts(_) => return,
                    }

                    log::debug!("CPMM > Pool creation accounts: {:?}", accounts);

                    if accounts.len() == 0 {
                        return;
                    }

                    if accounts[4] != WSOL_ADDRESS && accounts[5] != WSOL_ADDRESS {
                        return;
                    }

                    let token_address = if accounts[4] != WSOL_ADDRESS {
                        &accounts[4]
                    } else {
                        &accounts[5]
                    };
                    let token_program = if accounts[4] != WSOL_ADDRESS {
                        &accounts[15]
                    } else {
                        &accounts[16]
                    };
                    let deployer_address = &accounts[0];

                    let mint_data = {
                        let mints_lock = mints.lock().await;
                        mints_lock.iter().find(|(address, _, _, _)| address == token_address).cloned()
                    };
                    let deployer_data = {
                        let deployers_lock = deployers.lock().await;
                        deployers_lock.iter().find(|(address, _, _, _)| address == deployer_address).cloned()
                    };

                    log::debug!("CPMM > {} > Mint data: {:?}, Deployer data: {:?}", token_address, mint_data, deployer_data);
    
                    if mint_data.is_none() && deployer_data.is_none() {
                        log::debug!("CPMM > {} > Ignoring token", token_address);
                        return;
                    }
    
                    let (_, sol, jito_tip, slippage) = if mint_data.is_some() {
                        mint_data.unwrap()
                    } else if deployer_data.is_some() {
                        deployer_data.unwrap()
                    } else {
                        return;
                    };

                    log::debug!("CPMM > {} > Snipe height: {} SOL, Jito tip: {} SOL, Slippage: {} %", token_address, sol, jito_tip, slippage);
    
                    log::info!("CPMM > Found token: {}", token_address);
                    log::info!("CPMM > {} > Creating transaction", token_address);

                    let program_id = Pubkey::from_str(RAYDIUM_STANDARD_AMM_PROGRAM_ID).unwrap();
                    let authority = Pubkey::from_str(&accounts[2]).unwrap();
                    let amm_config = Pubkey::from_str(&accounts[1]).unwrap();
                    let pool_state = Pubkey::from_str(&accounts[3]).unwrap();
                    let input_vault = if accounts[4] != WSOL_ADDRESS {
                        Pubkey::from_str(&accounts[11]).unwrap()
                    } else {
                        Pubkey::from_str(&accounts[10]).unwrap()
                    };
                    let output_vault = if accounts[4] != WSOL_ADDRESS {
                        Pubkey::from_str(&accounts[10]).unwrap() 
                    } else {
                        Pubkey::from_str(&accounts[11]).unwrap()
                    };
                    let observation_state = Pubkey::from_str(&accounts[13]).unwrap();

                    log::debug!("CPMM > {} > Authority: {}, AMM config: {}, Pool state: {}, Input vault: {}, Output vault: {}, Observation state: {}", token_address, authority, amm_config, pool_state, input_vault, output_vault, observation_state);

                    log::info!("CPMM > {} > Requesting pool data", token_address);

                    let mut pool_retries = 0;

                    let pool = loop {
                        match rpc.get_account_with_config(&pool_state, RpcAccountInfoConfig {
                            encoding: Some(UiAccountEncoding::Base64),
                            commitment: Some(CommitmentConfig::confirmed()),
                            ..Default::default()
                        }).await {
                            Ok(pool) => {
                                if pool.value.is_none() {
                                    log::debug!("CPMM > {} > Pool not available yet: {}", token_address, pool_state.to_string());

                                    pool_retries += 1;
    
                                    if pool_retries >= MAX_RETRIES {
                                        log::error!("CPMM > Max retries reached in pool. Exiting loop.");
                                        return;
                                    }

                                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

                                    continue;
                                }

                                break pool
                            },
                            Err(e) => {
                                if !e.to_string().contains("invalid type: null") {
                                    log::error!("CPMM > Error getting pool data: {}", e);
                                } else {
                                    log::debug!("CPMM > Error getting pool data: {}", e);
                                }
    
                                pool_retries += 1;
    
                                if pool_retries >= MAX_RETRIES {
                                    log::error!("CPMM > Max retries reached in pool. Exiting loop.");
                                    return;
                                }
    
                                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await
                            }
                        }
                    };

                    log::debug!("CPMM > {} > Pool response: {:?}", token_address, pool);

                    let pool_open_time = PoolData::get_open_time(&pool.value.unwrap().data);

                    log::debug!("CPMM > {} > Pool open time: {}", token_address, pool_open_time);

                    let lamports = sol_to_lamports(sol);
                    let wsol_pubkey = Pubkey::from_str(WSOL_ADDRESS).unwrap();
    
                    let user_in_token_account = get_associated_token_address(
                        &keypair.pubkey(), 
                        &wsol_pubkey
                    );

                    let user_out_token_account = get_associated_token_address_with_program_id(
                        &keypair.pubkey(), 
                        &Pubkey::from_str(token_address).unwrap(), 
                        &Pubkey::from_str(token_program).unwrap(),
                    );
                    
                    let mut instructions = vec![];
                
                    let compute_unit_ix = ComputeBudgetInstruction::set_compute_unit_limit(120_000);
                    instructions.push(compute_unit_ix);
                    let compute_unit_price_ix = ComputeBudgetInstruction::set_compute_unit_price(*priority_fees);
                    instructions.push(compute_unit_price_ix);
                
                    let create_wsol_account_ix = create_associated_token_account_idempotent(
                        &keypair.pubkey(),
                        &keypair.pubkey(),
                        &Pubkey::from_str(WSOL_ADDRESS).unwrap(),
                        &Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap()
                    );
                    instructions.push(create_wsol_account_ix);
                
                    let transfer_ix = transfer(
                        &keypair.pubkey(), 
                        &user_in_token_account,
                        lamports
                    );
                    let sync_ix = sync_native(
                        &spl_token::ID, 
                        &user_in_token_account
                    ).unwrap();
                
                    instructions.push(transfer_ix);
                    instructions.push(sync_ix);
                
                    let create_token_account_ix = create_associated_token_account(
                        &keypair.pubkey(),
                        &keypair.pubkey(),
                        &Pubkey::from_str(token_address).unwrap(),
                        &Pubkey::from_str(&token_program).unwrap()
                    );
                    instructions.push(create_token_account_ix);

                    let min_amount_out = if slippage != 0.0 {
                        let token_price = if accounts[4] != WSOL_ADDRESS {
                            vault_1_amount / vault_0_amount
                        } else {
                            vault_0_amount / vault_1_amount
                        };

                        let max_amount_out = lamports as f64 / token_price;

                        log::debug!("CPMM > Token price: {}, amount max out: {}", token_price, max_amount_out);
                        
                        max_amount_out * (1.0 - slippage / 100.0)
                    } else {
                        0.0
                    } as u64;

                    log::debug!("CPMM > {} > Min amount out: {}", token_address, min_amount_out);

                    let mut data = Vec::with_capacity(8 + 8 + 8);
                    data.extend_from_slice(&STANDARD_AMM_SWAP_BASE_INPUT);
                    data.extend_from_slice(&lamports.to_le_bytes());
                    data.extend_from_slice(&min_amount_out.to_le_bytes());

                    let swap_ix = Instruction::new_with_bytes(
                        program_id, 
                        &data, 
                        vec![
                            AccountMeta::new_readonly(keypair.pubkey(), true),
                            AccountMeta::new_readonly(authority, false),
                            AccountMeta::new_readonly(amm_config, false),
                            AccountMeta::new(pool_state, false),
                            AccountMeta::new(user_in_token_account, false),
                            AccountMeta::new(user_out_token_account, false),
                            AccountMeta::new(input_vault, false),
                            AccountMeta::new(output_vault, false),
                            AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap(), false),
                            AccountMeta::new_readonly(Pubkey::from_str(token_program).unwrap(), false),
                            AccountMeta::new_readonly(wsol_pubkey, false),
                            AccountMeta::new_readonly(Pubkey::from_str(token_address).unwrap(), false),
                            AccountMeta::new(observation_state, false),
                        ]
                    );
                    instructions.push(swap_ix);
    
                    let close_account_ix = close_account(
                        &Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap(),
                        &user_in_token_account,
                        &keypair.pubkey(),
                        &keypair.pubkey(),
                        &[&keypair.pubkey()]
                    ).unwrap();
                    instructions.push(close_account_ix);
    
                    let transfer_ix = transfer(
                        &keypair.pubkey(), 
                        &Pubkey::from_str(&"DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL").unwrap(),
                        sol_to_lamports(jito_tip)
                    );
                    instructions.push(transfer_ix);

                    let now = Local::now();
                    let target_time = Local.timestamp_opt(pool_open_time as i64, 0).unwrap();
                    let duration = target_time - now;
                    let remaining_minutes = duration.num_minutes();
                    let remaining_seconds = duration.num_seconds() - remaining_minutes * 60;

                    if now < target_time {
                        log::info!("CPMM > {} > Pool closed. Proceeding with snipe in {}m {}s. UTC: {}", token_address, remaining_minutes, remaining_seconds, target_time.to_rfc2822());
                        
                        let duration = target_time - now;

                        tokio::time::sleep(duration.to_std().unwrap()).await;
                    
                        log::info!("CPMM > {} > Proceeding with snipe", token_address);
                    }

                    log::info!("CPMM > {} > Requesting latest blockhash", token_address);
                
                    let blockhash = rpc.get_latest_blockhash().await.unwrap();
    
                    log::debug!("CPMM > {} > Latest blockhash: {}", token_address, blockhash);

                    log::info!("CPMM > {} > Received latest blockhash", token_address);

                    let tx = Transaction::new_signed_with_payer(
                        &instructions,
                        Some(&keypair.pubkey()),
                        &[&keypair],
                        blockhash
                    );
    
                    log::info!("CPMM > {} > Transaction created", token_address);
                    log::info!("CPMM > {} > Starting swap", token_address);
    
                    let jito_rpc = RpcClient::new(jito_url.to_string());
    
                    let signature = jito_rpc.send_transaction_with_config(
                        &tx,
                        RpcSendTransactionConfig{
                        skip_preflight: true,
                        encoding: Some(UiTransactionEncoding::Base58),
                        max_retries: Some(0),
                        ..RpcSendTransactionConfig::default()
                    }).await.unwrap();
    
                    log::info!("CPMM > {} > Swap transaction signature: {}", token_address, signature);

                    //delete ca from mints.txt if token catched by address

                    log::info!("CPMM > {} > Waiting for 60s for the transaction to become available for fetching", token_address);
    
                    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    
                    log::info!("CPMM > {} > Fetching signature status", token_address);
    
                    let result = rpc.get_signature_status(&signature).await.unwrap();

                    log::debug!("CPMM > {} > Result: {:?}", token_address, result);
    
                    log::info!("CPMM > {} > Received signature status", token_address);

                    if result.is_none() {
                        log::error!("CPMM > {} > Jito auction failed", token_address);
    
                        return;
                    }
    
                    let result = result.unwrap();
    
                    if let Err(e) = result {
                        log::error!("CPMM > {} > Swap transaction failed: {}", token_address, e);
    
                        return;
                    }
    
                    log::info!("CPMM > {} > Successfully swapped {} SOL with {} SOL jito tip", token_address, sol, jito_tip);
                
                    let balance = rpc.get_balance(&keypair.pubkey()).await.unwrap();
    
                    log::info!("CPMM > {} > Balance: {} SOL", token_address, lamports_to_sol(balance));

                    return;
                }

                if !logs.iter().any(|log| log.contains(&RAYDIUM_V4_PROGRAM_ID.to_string()))
                    || !logs.iter().any(|log| log.contains(&"initialize2".to_string())) {
                    return;
                };
                let init_pc_amount_str = get_data_from_logs_by_regex(&logs, r"init_pc_amount: (\d+),");
                let init_pc_amount: f64 = init_pc_amount_str.unwrap().as_str().parse::<f64>().unwrap();

                let init_coin_amount_str = get_data_from_logs_by_regex(&logs, r"init_coin_amount: (\d+) }");
                let init_coin_amount: f64 = init_coin_amount_str.unwrap().as_str().parse::<f64>().unwrap();

                let timestamp_str = get_data_from_logs_by_regex(&logs, r"open_time: (\d+),");
                let timestamp: i64 = timestamp_str.unwrap().as_str().parse::<i64>().unwrap();

                log::debug!("OpenBook > init_pc_amount: {}, init_coin_amount: {}, open_time: {}", init_pc_amount, init_coin_amount, timestamp);

                let mut tx_retries = 0;

                let tx = loop {
                    match rpc.get_transaction_with_config(&signature, RpcTransactionConfig {
                        commitment: Some(CommitmentConfig::confirmed()),
                        max_supported_transaction_version: Some(0),
                        encoding: Some(UiTransactionEncoding::JsonParsed),
                    }).await {
                        Ok(tx) => break tx,
                        Err(e) => {
                            if !e.to_string().contains("invalid type: null") {
                                log::error!("OpenBook > Error getting transaction: {}", e);
                            } else {
                                log::debug!("OpenBook > Error getting transaction: {}", e);
                            }

                            tx_retries += 1;

                            if tx_retries >= MAX_RETRIES {
                                log::error!("OpenBook > Max retries reached in transaction. Exiting loop.");
                                return;
                            }

                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await
                        }
                    }
                };

                log::debug!("OpenBook > Pool creation transaction: {:?}", tx);

                let mut accounts: Vec<String> = vec![];

                match tx.transaction.transaction {
                    EncodedTransaction::LegacyBinary(_) => return,
                    EncodedTransaction::Binary(_, _) => return,
                    EncodedTransaction::Json(tx) => {
                        match tx.message {
                            UiMessage::Parsed(message) => {
                                for ix in message.instructions {
                                    match ix {
                                        UiInstruction::Compiled(_) => return,
                                        UiInstruction::Parsed(ix) => {
                                            match ix {
                                                UiParsedInstruction::Parsed(_) => continue,
                                                UiParsedInstruction::PartiallyDecoded(ix) => {
                                                    if ix.program_id == RAYDIUM_V4_PROGRAM_ID {
                                                        accounts = ix.accounts;

                                                        break;
                                                    }
                                                },
                                            }
                                        },
                                    }
                                }
                            },
                            UiMessage::Raw(_) => return,
                        }
                    },
                    EncodedTransaction::Accounts(_) => return,
                }

                log::debug!("OpenBook > Pool creation accounts: {:?}", accounts);

                if accounts.len() == 0 {
                    return;
                }

                if accounts[8] != WSOL_ADDRESS && accounts[9] != WSOL_ADDRESS {
                    return;
                }

                let token_address = if accounts[8] != WSOL_ADDRESS {
                    &accounts[8]
                } else {
                    &accounts[9]
                };
                let deployer_address = &accounts[17];

                let mint_data = {
                    let mints_lock = mints.lock().await;
                    mints_lock.iter().find(|(address, _, _, _)| address == token_address).cloned()
                };
                let deployer_data = {
                    let deployers_lock = deployers.lock().await;
                    deployers_lock.iter().find(|(address, _, _, _)| address == deployer_address).cloned()
                };

                log::debug!("OpenBook > {} > Mint data: {:?}, Deployer data: {:?}", token_address, mint_data, deployer_data);

                if mint_data.is_none() && deployer_data.is_none() {
                    log::debug!("OpenBook > {} > Ignoring token", token_address);
                    return;
                }

                let (_, sol, jito_tip, slippage) = if mint_data.is_some() {
                    mint_data.unwrap()
                } else if deployer_data.is_some() {
                    deployer_data.unwrap()
                } else {
                    return;
                };

                log::debug!("OpenBook > {} > Snipe height: {} SOL, Jito tip: {} SOL, Slippage: {} %", token_address, sol, jito_tip, slippage);

                log::info!("OpenBook > {} > Found token", token_address);
                log::info!("OpenBook > {} > Creating transaction", token_address);

                let program_id = RAYDIUM_V4_PROGRAM_ID;
                let id = Pubkey::from_str(&accounts[4]).unwrap();
                let authority = Pubkey::from_str(&accounts[5]).unwrap();
                let open_orders = Pubkey::from_str(&accounts[6]).unwrap();
                let base_vault = Pubkey::from_str(&accounts[10]).unwrap();
                let quote_vault = Pubkey::from_str(&accounts[11]).unwrap();
                let target_orders = Pubkey::from_str(&accounts[12]).unwrap();
                let market_program_id = Pubkey::from_str(&accounts[15]).unwrap();
                let market_id = Pubkey::from_str(&accounts[16]).unwrap();

                log::debug!("OpenBook > {} > ID: {}, Authority: {}, Open orders: {}, Base vault: {}, Quote vault: {}, Target orders: {}, Market program ID: {}, Market ID: {}", token_address, id, authority, open_orders, base_vault, quote_vault, target_orders, market_program_id, market_id);

                let lamports = sol_to_lamports(sol);
                let wsol_pubkey = Pubkey::from_str(WSOL_ADDRESS).unwrap();

                let user_in_token_account = get_associated_token_address(
                    &keypair.pubkey(), 
                    &wsol_pubkey
                );
                let user_out_token_account = get_associated_token_address(
                    &keypair.pubkey(), 
                    &Pubkey::from_str(token_address).unwrap()
                );
            
                let mut instructions = vec![];
            
                let compute_unit_ix = ComputeBudgetInstruction::set_compute_unit_limit(120_000);
                instructions.push(compute_unit_ix);
                let compute_unit_price_ix = ComputeBudgetInstruction::set_compute_unit_price(*priority_fees);
                instructions.push(compute_unit_price_ix);
            
                let create_wsol_account_ix = create_associated_token_account_idempotent(
                    &keypair.pubkey(),
                    &keypair.pubkey(),
                    &Pubkey::from_str(WSOL_ADDRESS).unwrap(),
                    &Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap()
                );
                instructions.push(create_wsol_account_ix);
            
                let transfer_ix = transfer(
                    &keypair.pubkey(), 
                    &user_in_token_account,
                    lamports
                );
                let sync_ix = sync_native(
                    &spl_token::ID, 
                    &user_in_token_account
                ).unwrap();
            
                instructions.push(transfer_ix);
                instructions.push(sync_ix);
            
                let create_token_account_ix = create_associated_token_account(
                    &keypair.pubkey(),
                    &keypair.pubkey(),
                    &Pubkey::from_str(token_address).unwrap(),
                    &Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap()
                );
                instructions.push(create_token_account_ix);

                log::info!("OpenBook > {} > Requesting market accounts", token_address);

                let market = match get_market_accounts(&rpc, &market_id).await {
                    Some(market) => market,
                    None => {
                        return;
                    }
                };

                log::debug!("OpenBook > {} > Market accounts: {:?}", token_address, market);

                log::info!("OpenBook > {} > Market accounts received", token_address);

                let min_amount_out = if slippage != 0.0 {
                    let token_price = if accounts[8] != WSOL_ADDRESS {
                        init_pc_amount / init_coin_amount
                    } else {
                        init_coin_amount / init_pc_amount
                    };

                    let max_amount_out = lamports as f64 / token_price;

                    log::debug!("OpenBook > {} > Token price: {}, amount max out: {}", token_address, token_price, max_amount_out);
                    
                    max_amount_out * (1.0 - slippage / 100.0)
                } else {
                    0.0
                } as u64;

                log::debug!("OpenBook > {} > Min amount out: {}", token_address, min_amount_out);

                let swap_ix = Instruction::new_with_borsh(
                    Pubkey::from_str(&program_id).unwrap(), 
                    &SwapInstructionBaseIn {
                        discriminator: 9,
                        amount_in: lamports,
                        minimum_amount_out: min_amount_out
                    }, 
                    vec![
                        // spl token
                        AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap(), false),
                        // amm
                        AccountMeta::new(id, false),
                        AccountMeta::new_readonly(authority, false),
                        AccountMeta::new(open_orders, false),
                        AccountMeta::new(target_orders, false),
                        AccountMeta::new(base_vault, false),
                        AccountMeta::new(quote_vault, false),
                        // serum
                        AccountMeta::new_readonly(market_program_id, false),
                        AccountMeta::new(market_id, false),
                        AccountMeta::new(market.state.bids, false),
                        AccountMeta::new(market.state.asks, false),
                        AccountMeta::new(market.state.event_queue, false),
                        AccountMeta::new(market.state.base_vault, false),
                        AccountMeta::new(market.state.quote_vault, false),
                        AccountMeta::new_readonly(get_associated_authority(
                            &market.program_id, 
                            &market.state.own_address
                        ).unwrap().0, false),
                        //user
                        AccountMeta::new(user_in_token_account, false),
                        AccountMeta::new(user_out_token_account, false),
                        AccountMeta::new_readonly(keypair.pubkey(), true),
                    ]
                );
                instructions.push(swap_ix);

                let close_account_ix = close_account(
                    &Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap(),
                    &user_in_token_account,
                    &keypair.pubkey(),
                    &keypair.pubkey(),
                    &[&keypair.pubkey()]
                ).unwrap();
                instructions.push(close_account_ix);

                let transfer_ix = transfer(
                    &keypair.pubkey(), 
                    &Pubkey::from_str(&"DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL").unwrap(),
                    sol_to_lamports(jito_tip)
                );
                instructions.push(transfer_ix);

                let now = Local::now();
                let target_time = Local.timestamp_opt(timestamp, 0).unwrap();
                let duration = target_time - now;
                let remaining_minutes = duration.num_minutes();
                let remaining_seconds = duration.num_seconds() - remaining_minutes * 60;

                if now < target_time {
                    log::info!("OpenBook > {} > Pool closed. Proceeding with snipe in {}m {}s. UTC: {}", token_address, remaining_minutes, remaining_seconds, target_time.to_rfc2822());
                
                    let duration = target_time - now;

                    tokio::time::sleep(duration.to_std().unwrap()).await;
                
                    log::info!("OpenBook > {} > Proceeding with snipe", token_address);
                }
            
                log::info!("OpenBook > {} > Requesting latest blockhash", token_address);

                let blockhash = rpc.get_latest_blockhash().await.unwrap();

                log::debug!("OpenBook > {} > Latest blockhash: {}", token_address, blockhash);

                log::info!("OpenBook > {} > Received latest blockhash", token_address);

                let tx = Transaction::new_signed_with_payer(
                    &instructions,
                    Some(&keypair.pubkey()),
                    &[&keypair],
                    blockhash
                );

                log::info!("OpenBook > {} > Transaction created", token_address);
                log::info!("OpenBook > {} > Starting swap", token_address);

                let jito_rpc = RpcClient::new(jito_url.to_string());

                let signature = jito_rpc.send_transaction_with_config(
                    &tx,
                    RpcSendTransactionConfig{
                    skip_preflight: true,
                    encoding: Some(UiTransactionEncoding::Base58),
                    max_retries: Some(0),
                    ..RpcSendTransactionConfig::default()
                }).await.unwrap();

                log::info!("OpenBook > {} > Swap transaction signature: {}", token_address, signature);

                //delete ca from mints.txt if token catched by address

                log::info!("OpenBook > {} > Waiting for 60s for the transaction to become available for fetching", token_address);

                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

                log::info!("OpenBook > {} > Fetching signature status", token_address);

                let result = rpc.get_signature_status(&signature).await.unwrap();

                log::debug!("OpenBook > {} > Result: {:?}", token_address, result);

                log::info!("OpenBook > {} > Received signature status", token_address);

                if result.is_none() {
                    log::error!("OpenBook > {} > Jito auction failed", token_address);

                    return;
                }

                let result = result.unwrap();

                if let Err(e) = result {
                    log::error!("OpenBook > {} > Swap transaction failed: {}", token_address, e);

                    return;
                }

                log::info!("OpenBook > {} > Successfully swapped {} SOL with {} SOL jito tip", token_address, sol, jito_tip);
            
                let balance = rpc.get_balance(&keypair.pubkey()).await.unwrap();

                log::info!("OpenBook > {} > Balance: {} SOL", token_address, lamports_to_sol(balance));
            });
        }

        let _ = ws.0.send_unsubscribe();

        log::warn!("Connection lost, attempting to reconnect in 5 seconds...");

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}

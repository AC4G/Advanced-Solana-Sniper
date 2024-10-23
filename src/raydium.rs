use std::{str::FromStr, sync::Arc};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_account_decoder::UiAccountEncoding;
use solana_client::{client_error::ClientError, nonblocking::rpc_client::RpcClient, rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig}, rpc_filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType}};
use solana_sdk::{account::Account, commitment_config::CommitmentConfig, program_error::ProgramError, pubkey::Pubkey};
use futures::join;
use crate::MAX_RETRIES;

pub const STANDARD_AMM_SWAP_BASE_INPUT: [u8; 8] = [143, 190, 90, 218, 196, 30, 51, 222];
pub const RAYDIUM_STANDARD_AMM_PROGRAM_ID: &str = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";
pub const RAYDIUM_V4_PROGRAM_ID: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const WSOL_ADDRESS: &str = "So11111111111111111111111111111111111111112";

#[derive(BorshSerialize, BorshDeserialize)]
pub struct SwapInstructionBaseIn {
    pub discriminator: u8,
    pub amount_in: u64,
    pub minimum_amount_out: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct PoolData {
    pub amm_config: Pubkey,
    pub pool_creator: Pubkey,
    pub token_0_vault: Pubkey,
    pub token_1_vault: Pubkey,
    pub lp_mint: Pubkey,
    pub token_0_mint: Pubkey,
    pub token_1_mint: Pubkey,
    pub token_0_program: Pubkey,
    pub token_1_program: Pubkey,
    pub observation_key: Pubkey,
    pub auth_bump: u8,
    pub status: u8,
    pub lp_mint_decimals: u8,
    pub mint_0_decimals: u8,
    pub mint_1_decimals: u8,
    pub lp_supply: u64,
    pub protocol_fees_token_0: u64,
    pub protocol_fees_token_1: u64,
    pub fund_fees_token_0: u64,
    pub fund_fees_token_1: u64,
    pub open_time: u64,
    pub padding: [u64; 32],
}

impl PoolData {
    pub fn get_open_time(data: &Vec<u8>) -> u64 {
        u64::from_le_bytes(data[373..381].try_into().ok().unwrap())
    }
}

pub async fn get_program_accounts(rpc: &Arc<RpcClient>, base_mint: &str, quote_mint: &str) -> Result<Vec<(Pubkey, Account)>, ClientError> {
    let raydium_program_pubkey = Pubkey::from_str(RAYDIUM_V4_PROGRAM_ID)
        .expect("Invalid raydium program id");

    let filters = Some(vec![
        RpcFilterType::DataSize(752),
        RpcFilterType::Memcmp(Memcmp::new(
            400, 
            MemcmpEncodedBytes::Base58(base_mint.to_string())
        )),
        RpcFilterType::Memcmp(Memcmp::new(
            432, 
            MemcmpEncodedBytes::Base58(quote_mint.to_string())
        )),
    ]);

    rpc.get_program_accounts_with_config(
        &raydium_program_pubkey,
        RpcProgramAccountsConfig {
            filters,
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                commitment: Some(rpc.commitment()),
                ..RpcAccountInfoConfig::default()
            },
            ..RpcProgramAccountsConfig::default()
        }
    ).await
}

pub async fn find_raydium_pool_info(rpc: &Arc<RpcClient>, base_mint: &str, quote_mint: &str) -> Option<LiquidityPoolKeys> {
    let mut attempt = 0;
    let max_attmepts = 100;

    let program_data_result: Option<Vec<(Pubkey, Account)>> = loop {
        let (program_data_0, program_data_1) = join!(
            get_program_accounts(&rpc, base_mint, quote_mint),
            get_program_accounts(&rpc, quote_mint, base_mint)
        );

        let program_data_0 = program_data_0.unwrap();
        let program_data_1 = program_data_1.unwrap();

        if program_data_0.len() == 0 && program_data_1.len() == 0 {
            if attempt == max_attmepts {
                return None
            }

            attempt += 1;
            continue;
        }

        if program_data_0.len() > 0 {
            break Some(program_data_0)
        } else {
            break Some(program_data_1)
        }
    };

    let collected_pool_results = match program_data_result {
        Some(program_data) => {
            program_data
                .into_iter()
                .map(|(pubkey, account)| {
                    LiquidityPool {
                        id: pubkey,
                        version: 4,
                        program_id: Pubkey::from_str(RAYDIUM_V4_PROGRAM_ID).unwrap(),
                        state: LiquidityStateLayoutV4::decode(&account.data.as_slice()).unwrap()
                    }
                })
                .collect::<Vec<_>>()
        },
        None => {
            return None
        }
    };

    let pool_result = collected_pool_results.get(0);

    if pool_result.is_none() {
        return None
    }

    let pool = pool_result.unwrap();

    let market = match get_market_accounts(&rpc, &pool.state.market_id).await {
        Some(market) => market,
        None => {
            return None
        }
    };

    let seeds: &[&[u8]] = &[&[97, 109, 109, 32, 97, 117, 116, 104, 111, 114, 105, 116, 121]];
    let authority = Pubkey::find_program_address(
        seeds, 
        &Pubkey::from_str(RAYDIUM_V4_PROGRAM_ID).unwrap()
    ).0;

    Some(LiquidityPoolKeys {
        id: pool.id,
        base_mint: pool.state.base_mint,
        quote_mint: pool.state.quote_mint,
        lp_mint: pool.state.lp_mint,
        base_decimals: pool.state.base_decimal,
        quote_decimals: pool.state.quote_decimal,
        lp_decimals: pool.state.base_decimal,
        version: pool.version,
        program_id: pool.program_id,
        authority: authority,
        open_orders: pool.state.open_orders,
        target_orders: pool.state.target_orders,
        base_vault: pool.state.base_vault,
        quote_vault: pool.state.quote_vault,
        withdraw_queue: pool.state.withdraw_queue,
        lp_vault: pool.state.lp_vault,
        market_version: 3,
        market_program_id: market.program_id,
        market_id: market.state.own_address,
        market_authority: get_associated_authority(
            &market.program_id, 
            &market.state.own_address
        ).unwrap().0,
        market_base_vault: market.state.base_vault,
        market_quote_vault: market.state.quote_vault,
        market_bids: market.state.bids,
        market_asks: market.state.asks,
        market_event_queue: market.state.event_queue,
        swap_base_in_amount: pool.state.swap_base_in_amount,
        swap_quote_out_amount: pool.state.swap_quote_out_amount
    })
}

pub async fn get_market_accounts(rpc: &Arc<RpcClient>, market_id: &Pubkey) -> Option<Market> {
    let mut attempt = 0;

    loop {
        let market_account_info_result = rpc.get_account_with_commitment(&market_id, CommitmentConfig::confirmed()).await;

        match market_account_info_result {
            Ok(market_account_info) => {
                let market_account_info = market_account_info.value.unwrap();

                return Some(Market {
                    program_id: market_account_info.owner,
                    state: MarketStateLayoutV3::decode(&market_account_info.data.as_slice()).unwrap(),
                })
            },
            Err(e) => {
                log::debug!("Error getting market accounts: {:?}", e);

                if attempt == MAX_RETRIES {
                    return None
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

        attempt += 1;
    }
}

pub fn get_associated_authority(program_id: &Pubkey, market_id: &Pubkey) -> Result<(Pubkey, u64), ProgramError> {
    let mut nonce: u64 = 0;

    while nonce < 100 {
        let seeds_with_nonce: [&[u8]; 3] = [&market_id.to_bytes(), &nonce.to_le_bytes(), &[0u8; 7]];

        match Pubkey::try_find_program_address(&seeds_with_nonce, &program_id) {
            Some((pubkey, _)) => return Ok((pubkey, nonce)),
            None => nonce += 1
        }
    }

    Err(ProgramError::Custom(1))
}

#[derive(Debug)]
pub struct OwnerTokenAccounts {
    pub pubkey: Pubkey,
    pub program_id: Pubkey,
    pub account_info: SplAccountLayout
}

#[derive(Debug)]
pub struct SplAccountLayout {
    pub mint: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub delegate_option: u32,
    pub delegate: Pubkey,
    pub state: u8,
    pub is_native_option: u32,
    pub is_native: u64,
    pub delegated_amount: u64,
    pub close_authority_option: u32,
    pub close_authority: Pubkey,
}

impl SplAccountLayout {
    #[allow(dead_code)]
    pub fn span() -> u64 {
        std::mem::size_of::<Self>() as u64
    }

    #[allow(dead_code)]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::span() as usize {
            return None;
        }

        let mut offset = 0;

        macro_rules! read_field {
            ($ty:ty) => {{
                let value = <$ty>::from_le_bytes(bytes[offset..offset + std::mem::size_of::<$ty>()].try_into().ok()?);
                offset += std::mem::size_of::<$ty>();
                value
            }};
        }

        Some(SplAccountLayout {
            mint: Pubkey::new_from_array(bytes[offset..offset + 32].try_into().unwrap()),
            owner: Pubkey::new_from_array(bytes[offset..offset + 32].try_into().unwrap()),
            amount: read_field!(u64),
            delegate_option: read_field!(u32),
            delegate: Pubkey::new_from_array(bytes[offset..offset + 32].try_into().unwrap()),
            state: read_field!(u8),
            is_native_option: read_field!(u32),
            is_native: read_field!(u64),
            delegated_amount: read_field!(u64),
            close_authority_option: read_field!(u32),
            close_authority: Pubkey::new_from_array(bytes[offset..offset + 32].try_into().unwrap()),
        })
    }
}

#[derive(Debug)]
pub struct LiquidityPoolKeys {
    pub id: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub lp_mint: Pubkey,
    pub base_decimals: u64,
    pub quote_decimals: u64,
    pub lp_decimals: u64,
    pub version: u64,
    pub program_id: Pubkey,
    pub authority: Pubkey,
    pub open_orders: Pubkey,
    pub target_orders: Pubkey,
    pub base_vault: Pubkey,
    pub quote_vault: Pubkey,
    pub withdraw_queue: Pubkey,
    pub lp_vault: Pubkey,
    pub market_version: u64,
    pub market_program_id: Pubkey,
    pub market_id: Pubkey,
    pub market_authority: Pubkey,
    pub market_base_vault: Pubkey,
    pub market_quote_vault: Pubkey,
    pub market_bids: Pubkey,
    pub market_asks: Pubkey,
    pub market_event_queue: Pubkey,
    pub swap_base_in_amount: u128,
    pub swap_quote_out_amount: u128
}

#[derive(Debug)]
pub struct Market {
    pub program_id: Pubkey,
    pub state: MarketStateLayoutV3
}

#[derive(Debug)]
pub struct MarketStateLayoutV3 {
    _padding1: [u8; 5],
    pub account_flags: [u8; 8],
    pub own_address: Pubkey,
    pub vault_signer_nonce: u64,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub base_vault: Pubkey,
    pub base_deposits_total: u64,
    pub base_fees_accrued: u64,
    pub quote_vault: Pubkey,
    pub quote_deposits_total: u64,
    pub quote_fees_accrued: u64,
    pub quote_dust_threshold: u64,
    pub request_queue: Pubkey,
    pub event_queue: Pubkey,
    pub bids: Pubkey,
    pub asks: Pubkey,
    pub base_lot_size: u64,
    pub quote_lot_size: u64,
    pub fee_rate_bps: u64,
    pub referrer_rebates_accrued: u64,
    _padding2: [u8; 7],
}

impl MarketStateLayoutV3 {
    #[allow(dead_code)]
    pub fn span() -> u64 {
        std::mem::size_of::<Self>() as u64
    }

    pub fn decode(bytes: &[u8]) -> Option<MarketStateLayoutV3> {
        if bytes.len() != 388 {
            return None;
        }
    
        let mut offset = 5;
    
        macro_rules! read_field {
            ($ty:ty) => {{
                let value = <$ty>::from_le_bytes(bytes[offset..offset + std::mem::size_of::<$ty>()].try_into().ok()?);
                offset += std::mem::size_of::<$ty>();
                value
            }};
        }
    
        Some(MarketStateLayoutV3 {
            _padding1: [0u8; 5],
            account_flags: bytes[offset..offset + 8].try_into().unwrap(),
            own_address: Pubkey::new_from_array(bytes[offset + 8..offset + 40].try_into().unwrap()),
            vault_signer_nonce: read_field!(u64),
            base_mint: Pubkey::new_from_array(bytes[offset + 40..offset + 72].try_into().unwrap()),
            quote_mint: Pubkey::new_from_array(bytes[offset + 72..offset + 104].try_into().unwrap()),
            base_vault: Pubkey::new_from_array(bytes[offset + 104..offset + 136].try_into().unwrap()),
            base_deposits_total: read_field!(u64),
            base_fees_accrued: read_field!(u64),
            quote_vault: Pubkey::new_from_array(bytes[offset + 136..offset + 168].try_into().unwrap()),
            quote_deposits_total: read_field!(u64),
            quote_fees_accrued: read_field!(u64),
            quote_dust_threshold: read_field!(u64),
            request_queue: Pubkey::new_from_array(bytes[offset + 168..offset + 200].try_into().unwrap()),
            event_queue: Pubkey::new_from_array(bytes[offset + 200..offset + 232].try_into().unwrap()),
            bids: Pubkey::new_from_array(bytes[offset + 232..offset + 264].try_into().unwrap()),
            asks: Pubkey::new_from_array(bytes[offset + 264..offset + 296].try_into().unwrap()),
            base_lot_size: read_field!(u64),
            quote_lot_size: read_field!(u64),
            fee_rate_bps: read_field!(u64),
            referrer_rebates_accrued: read_field!(u64),
            _padding2: [0u8; 7],
        })
    }
}

#[derive(Debug, Clone)]
pub struct LiquidityPool {
    pub id: Pubkey,
    pub version: u64,
    pub program_id: Pubkey,
    pub state: LiquidityStateLayoutV4,
}

#[derive(Debug, Clone)]
pub struct LiquidityStateLayoutV4 {
    pub status: u64,
    pub nonce: u64,
    pub max_order: u64,
    pub depth: u64,
    pub base_decimal: u64, //
    pub quote_decimal: u64, //
    pub state: u64,
    pub reset_flag: u64,
    pub min_size: u64,
    pub vol_max_cut_ratio: u64,
    pub amount_wave_ratio: u64,
    pub base_lot_size: u64,
    pub quote_lot_size: u64,
    pub min_price_multiplier: u64,
    pub max_price_multiplier: u64,
    pub system_decimal_value: u64,
    pub min_separate_numerator: u64,
    pub min_separate_denominator: u64,
    pub trade_fee_numerator: u64,
    pub trade_fee_denominator: u64,
    pub pnl_numerator: u64,
    pub pnl_denominator: u64,
    pub swap_fee_numerator: u64,
    pub swap_fee_denominator: u64,
    pub base_need_take_pnl: u64,
    pub quote_need_take_pnl: u64,
    pub quote_total_pnl: u64,
    pub base_total_pnl: u64,
    pub pool_open_time: u64,
    pub punish_pc_amount: u64,
    pub punish_coin_amount: u64,
    pub orderbook_to_init_time: u64,
    pub swap_base_in_amount: u128, //
    pub swap_quote_out_amount: u128, //
    pub swap_base_2_quote_fee: u64,
    pub swap_quote_in_amount: u128,
    pub swap_base_out_amount: u128,
    pub swap_quote_2_base_fee: u64,
    pub base_vault: Pubkey,
    pub quote_vault: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub lp_mint: Pubkey,
    pub open_orders: Pubkey,
    pub market_id: Pubkey,
    pub market_program_id: Pubkey,
    pub target_orders: Pubkey,
    pub withdraw_queue: Pubkey,
    pub lp_vault: Pubkey,
    pub owner: Pubkey,
    pub lp_reserve: u64,
    pub padding: [u64; 3],
}

impl LiquidityStateLayoutV4 {
    pub fn span() -> u64 {
        std::mem::size_of::<Self>() as u64
    }

    pub fn decode(bytes: &[u8]) -> Option<LiquidityStateLayoutV4> {
        if bytes.len() != Self::span() as usize {
            return None;
        }

        let mut offset = 0;

        macro_rules! read_field {
            ($ty:ty) => {{
                let value = <$ty>::from_le_bytes(bytes[offset..offset + std::mem::size_of::<$ty>()].try_into().ok()?);
                offset += std::mem::size_of::<$ty>();
                value
            }};
        }

        Some(LiquidityStateLayoutV4 {
            status: read_field!(u64),
            nonce: read_field!(u64),
            max_order: read_field!(u64),
            depth: read_field!(u64),
            base_decimal: read_field!(u64),
            quote_decimal: read_field!(u64),
            state: read_field!(u64),
            reset_flag: read_field!(u64),
            min_size: read_field!(u64),
            vol_max_cut_ratio: read_field!(u64),
            amount_wave_ratio: read_field!(u64),
            base_lot_size: read_field!(u64),
            quote_lot_size: read_field!(u64),
            min_price_multiplier: read_field!(u64),
            max_price_multiplier: read_field!(u64),
            system_decimal_value: read_field!(u64),
            min_separate_numerator: read_field!(u64),
            min_separate_denominator: read_field!(u64),
            trade_fee_numerator: read_field!(u64),
            trade_fee_denominator: read_field!(u64),
            pnl_numerator: read_field!(u64),
            pnl_denominator: read_field!(u64),
            swap_fee_numerator: read_field!(u64),
            swap_fee_denominator: read_field!(u64),
            base_need_take_pnl: read_field!(u64),
            quote_need_take_pnl: read_field!(u64),
            quote_total_pnl: read_field!(u64),
            base_total_pnl: read_field!(u64),
            pool_open_time: read_field!(u64),
            punish_pc_amount: read_field!(u64),
            punish_coin_amount: read_field!(u64),
            orderbook_to_init_time: read_field!(u64),
            swap_base_in_amount: u128::from_le_bytes(bytes[offset..offset + 16].try_into().ok()?),
            swap_quote_out_amount: u128::from_le_bytes(bytes[offset + 16..offset + 32].try_into().ok()?),
            swap_base_2_quote_fee: read_field!(u64),
            swap_quote_in_amount: u128::from_le_bytes(bytes[offset + 32..offset + 48].try_into().ok()?),
            swap_base_out_amount: u128::from_le_bytes(bytes[offset + 48..offset + 64].try_into().ok()?),
            swap_quote_2_base_fee: read_field!(u64),
            base_vault: Pubkey::new_from_array(bytes[offset + 64..offset + 96].try_into().unwrap()),
            quote_vault: Pubkey::new_from_array(bytes[offset + 96..offset + 128].try_into().unwrap()),
            base_mint: Pubkey::new_from_array(bytes[offset + 128..offset + 160].try_into().unwrap()),
            quote_mint: Pubkey::new_from_array(bytes[offset + 160..offset + 192].try_into().unwrap()),
            lp_mint: Pubkey::new_from_array(bytes[offset + 192..offset + 224].try_into().unwrap()),
            open_orders: Pubkey::new_from_array(bytes[offset + 224..offset + 256].try_into().unwrap()),
            market_id: Pubkey::new_from_array(bytes[offset + 256..offset + 288].try_into().unwrap()),
            market_program_id: Pubkey::new_from_array(bytes[offset + 288..offset + 320].try_into().unwrap()),
            target_orders: Pubkey::new_from_array(bytes[offset + 320..offset + 352].try_into().unwrap()),
            withdraw_queue: Pubkey::new_from_array(bytes[offset + 352..offset + 384].try_into().unwrap()),
            lp_vault: Pubkey::new_from_array(bytes[offset + 384..offset + 416].try_into().unwrap()),
            owner: Pubkey::new_from_array(bytes[offset + 416..offset + 448].try_into().unwrap()),
            lp_reserve: read_field!(u64),
            padding: [
                read_field!(u64),
                read_field!(u64),
                read_field!(u64),
            ]
        })
    }
}


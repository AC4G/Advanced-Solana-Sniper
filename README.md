## Advanced Solana Sniper by MINT CA and Deployer address


This sniper is written in rust for speed and safety.
The sniper also has a reduced amount of rpc calls to increase speed
of sniping right after catching pool creation in ``confirmed`` commitment. 
Sniping is being done with jito to increase the likelyhood of success.

It can snipe only raydium pools: 
- OpenBook
- CPMM

## How to use it

1. Copy ``.env.example`` and rename it to ``.env``
2. paste the rpc and wss url in ``.env``
3. Generate a keypair.json with solana cli
4. Deposit some SOL in the new generated wallet
5. Now set the MINT CA into mints.txt in ``addys/mints|snipe height|jito tip|slippage`` format or 
    ``account address|snipe height|jito tip|slippage`` in deployers.txt to snipe by deployer.
6. Ensure that Rust and ``cargo`` are installed.
7. Start the sniper with ``cargo run --release``

## Disclaimer

I am not liable for any losses nor wins caused by this program.
Please use at your own risk. I am not responsible for any damages.

## PS

On further request I can improve the README and how to use the sniper as a linux service in the background with systemd.


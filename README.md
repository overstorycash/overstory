# Overstory

Fully on-chain generative trees on Zcash.

Source is available ahead of mint so you can build the CLI, prepare your own
Zcash node or compatible RPC, and replay the project index from genesis.
Mint is not open yet. The announced collection start height controls eligibility;
source availability does not allow an early mint. Do not send funds to a preview
page or an unverified address.

## Official mainnet launch parameters

Mint starts at block **3,526,433**, approximately October 22, 2026 at 07:08 UTC (15:08 UTC+8). Block production varies; the height, not the estimated clock time, is authoritative.

- Collection:`7255d20a586fa665c5d66a61b71f2f0a31f715597922e8e30b526f759faf44a2i0`
- Supply: 3,000. No per-address cap, reserved allocation or priority mint path.
- Self-service mint price: 0.05 ZEC (5,000,000 zat), plus carrier value and network fees.
- Mint payment address:`t1f7JPjEc8drDirsJfpMwbcdrWCHS7whgrt`
- Optional mint service: 0.10 ZEC total, including mint price and network fees. Do not pay until an official invoice is available.
- Renderer:`51f848e31c5bf0ed38c5936129915a24fb08a85074c4c0d650be5de47671eec0i0`
- Renderer SHA256:`67b00f3dedee8a93014b6e8da71795f1766d91b5028892d587140aa96f221f42`
- Mainnet genesis:`00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08`

After backing up your private key and completing the full index, use the command below **at the opening height**. It signs and broadcasts real mainnet transactions:

```sh
"$PROTO" mint vault 7255d20a586fa665c5d66a61b71f2f0a31f715597922e8e30b526f759faf44a2i0 YOUR_DESTINATION_ADDRESS t1f7JPjEc8drDirsJfpMwbcdrWCHS7whgrt 5000000
```

Source publication is for advance preparation. Neither a payment nor a broadcast reserves a mint number. The official market remains closed during mint and opens only after sellout and index verification. Website outages or an invoice pause cannot stop independent protocol participants.

## Included source

- `docs/PROTOCOL.md`: draft protocol.
- `crates/proto`: self-service CLI, with its workspace dependencies and lockfile.
- `crates/render` and `render/`: Rust and Python reference rendering.
- `crates/mintd`: service source; production configuration and web UI are excluded.
- `crates/sighash-wasm`: signing implementation; no compiled browser bundle.
- `crates/vendor/zcash_transparent`: patched dependency with upstream licenses.
- `web/security-policy.txt`: compile-time policy dependency only.
- Three explicitly listed `regtest/*.rs` Cargo examples: isolated acceptance
  fixtures, not a production index or a substitute for replay from genesis.

No wallet, deployment configuration, private operations documentation, runtime
state, hosted RPC credentials or project-provided index snapshot is included.
A recent Rust toolchain with edition 2024 support is required (the bundled
transparent crate requires Rust 1.88 or newer). Registry dependencies may need
to be downloaded by Cargo; the source packaging process makes no network calls.

## Self-service CLI workflow (pre-release)

Self-service users supply their own Zcash JSON-RPC endpoint. The project does not provide a self-service RPC relay. Public website snapshots do not replace the RPC needed to verify inputs and broadcast. The optional mint service has a separate invoice flow; do not send a self-service payment to a service invoice address.

Build from the reviewed source with Rust/Cargo and the checked-in lockfile:

```sh
cargo build --locked --release -p proto
```

The examples below use a POSIX shell and a separate private runtime directory. On Windows, use the corresponding `proto.exe` path and secure the directory with your user ACL. Do not run wallet commands from a directory served by a web server.

```sh
umask 077
mkdir overstory-wallet
cd overstory-wallet
# Set this to the absolute path of the binary you just built.
PROTO=/absolute/path/to/zec-trees/target/release/proto
```

Using a local editor, create `rpc.url` containing your endpoint on one line (treat authenticated URLs as credentials). For a local Zebra node with cookie authentication, keep `rpc.url` credential-free (for example `http://127.0.0.1:8232`) and set `OVERSTORY_RPC_COOKIE_FILE` to its cookie file. The process needs read permission; the cookie is reloaded on every request. Cookie mode only accepts literal loopback HTTP addresses with explicit ports. RPC redirects are rejected. Never copy the cookie into source control or logs. Create `chain.json` with these official mainnet fields, checking the genesis against independent network information:

```json
{"network":"mainnet","genesis_hash":"00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"}
```

Use separate runtime directories and keys for each network. Do not copy the genesis hash from an unverified RPC response and automatically trust it. The CLI checks the selected network, pinned genesis and supported upgrade schedule before transactions.

Your endpoint must support the methods used by this workflow: `getblockchaininfo`, `getblockhash`, `getblock`, `getblockcount`, `getaddressutxos`, `getrawtransaction`, `gettxout` and `sendrawtransaction`. Verify method availability, historical data access and provider limits before funding. A lightwalletd/gRPC endpoint is not a substitute for this JSON-RPC interface.

```sh
"$PROTO" keygen vault
"$PROTO" addr vault
```

Back up `keys/vault.key` offline before funding the displayed address. Never publish the runtime, private key or authenticated endpoint. Fund only the selected network, allowing for the frozen mint price, carrier value and transaction fees. Keep the entire runtime backed up as it accumulates signed plans and recovery records.

```sh
"$PROTO" index --max-blocks 100
```

`--max-blocks` accepts 1–10,000 and bounds newly processed blocks per invocation, not total RPC calls or credits. Run the same command again to resume from the last committed block. Do not mint until the index reaches the chain tip. Omitting the option retains the legacy unbounded replay, so use an explicit limit with a metered provider. Invalid limits are rejected before RPC access.

**Launch participation policy:** self-service participants prepare their own node or compatible RPC and independently replay the index from genesis. The project does not distribute or endorse index snapshots. Community snapshots are third-party data whose trust and correctness users must assess themselves; a file checksum alone does not prove index correctness. Allow substantial time, disk and RPC capacity before minting. The protocol and preparation requirements may be published before launch. The implementation may be published before mint opens so participants can build and replay the index in advance. Publishing source does not open mint: the official collection start height controls the first eligible block. Self-service, team minting and the optional mint service use the same start height. Do not skip history manually; readiness depends on your hardware and RPC access.

Once the index is current, compare its collection ID, payment address and price with the official frozen release parameters. The official collection and fixed terms are listed above. Verify them against your independently replayed index. The following command **signs and broadcasts** and is shown only as a template:

```sh
"$PROTO" mint vault OFFICIAL_COLLECTION_ID YOUR_DESTINATION_ADDRESS OFFICIAL_PAYMENT_ADDRESS PRICE_IN_ZAT
```

The optional payment arguments assert the expected indexed terms. `PRICE_IN_ZAT` is an integer (100,000,000 zat = 1 ZEC); network fees are additional to the self-service mint price. A submitted payment does not reserve a mint number. Check the indexed result after confirmation; the market stays closed until minting completes, indexing is verified and the operator explicitly opens it.

If submission loses its response, preserve the runtime and the printed `saved CLI inscription plan` ID. Check the saved transactions before retrying. Recovery uses the same signed plan:

```sh
"$PROTO" inscribe-resume SAVED_INSCRIPTION_ID
```

Do not issue a fresh `mint` as a replacement for an uncertain transaction. Expired or conflicting plans require reconciliation; resume is not a guarantee that an expired transaction can be mined.

## License

MIT; see `LICENSE`. Bundled third-party components retain their own licenses.

# PP-H2 recorded run: Hank's trading card, contract-signed, live

Run on 2026-11-12, NEAR testnet and PayPal sandbox only, with `demo/src/pt2-hank-live.ts` as of its pre-merge commit `d0e7deb`. Transcript: [pt2-hank-live.jsonl](pt2-hank-live.jsonl), one JSON line per step, written by the script; the last line was added by hand (see Notes). It holds no key, token or full email; payees are masked as the rail masks them. Invoice ids are sandbox invoices, order, capture and payout batch ids are sandbox ids, tx hashes are NEAR testnet.

## Setup (`demo/src/pt2-hank-setup.ts`)

| Part | Value |
|---|---|
| Mandate contract | `nearh-ph2-1794482268.testnet`, fresh faucet account. Deploy + `new` tx `J288W8xnqH7NFcXgmVBrPBtRV8AJbsApSKcUJCWyGWkz` |
| Owner | NEAR wallet `nearh-ph2-own-1794482268.testnet` (wallet mode, 1 yoctoNEAR and `assertion: null`, as PP-L1) |
| Agent | `grokbot-hank`, function-call key only, EOA `0x3adad8c715e4c38a5147244fd71997f8166a0927` (derive(contract, agent), equal to the MPC's `derived_public_key` view). `add_agent` tx `Cm3k1eZ2R4zzbPKM7cqYQyJG5vgwuDFMA9tz2DEtunge` |
| Mandate | `paypal`: USD 0.01–100.00 per payment, USD 150.00 per week, `max_validity_secs` 300. `set_mandate` tx `7cThNSczHkmUtLbuxq9k3kYZmwms4jKRsNkMBTjMmuPX` |
| Merchants | `sb…@personal.example.com` (a PayPal sandbox account, standing in for the real card shop; tx `3ZU7Gg8g8ADppX7pZDTgs71gHfVo43XraZBNkPc7FzNp`), `or…@dragonden.example` (tx `2xCJsJ34aiqHpcxJo3zpz74BjuEAd25uJPggoikd7JVc`), `sh…@holohaven.example` (tx `13YH4GmmoTnTqseKRFsodomwQ8qpb6vKK67iMXm1cqsC`) |
| Full-access key | deleted, tx `BK5vKja1jBi8sdmfCRBqGHMeyBfRqWQy3c53HBaXQiZY` |
| Vault | Hank's PayPal wallet vaulted through the rail's `/vault/connect`; the owner approved PayPal's link as the sandbox personal buyer, then `/vault/confirm` stored the payment token in the rail (status `active`) |
| Rail | `rails/paypal` `pnpm start` (PP3) with the vault routes on, 127.0.0.1:8789: the only process with the PayPal sandbox credentials and the vault token |
| Buyer agent | agent/mcp's `Buyer.payPaypal` (`pay_paypal`, `mode: checkout`), wired by `createBuyerFromEnv` as the MCP server wires it, called by the script (Grokbot did not drive it). Its process has no PayPal credential |
| Scam check | SC1 with `google/gemini-2.5-flash-lite` on NEAR AI Cloud |

## The beats

| Beat | Invoice | Scam check | Contract | PayPal / rail |
|---|---|---|---|---|
| fake | `INV2-NVLY-T5PK-5L4B-TKFW`, USD 39.00 to `sa…@cardvau1t.example` | **held**: `unknown payee` | not called | nothing |
| fake, check stubbed (the AI fooled) | `INV2-U8JF-QUVM-FP8Q-NTEY`, same | stub: ok | **refused on chain**: `ERR_PAYPAL_PAYEE_NOT_ALLOWED`, failed tx `8B5wdduqRxvnJHwdqTjXujdBpjbs6LsfoF4NyRfmPFuj` | nothing |
| bait | `INV2-YQL4-7B2C-QMEP-Y3FW`, USD 149.00 to `sh…@holohaven.example` (allowed shop, cap USD 100.00) | **held**: amount above what the listing text asks | not called | nothing |
| bait, check stubbed | `INV2-AGTV-3N77-PGVB-7GHF`, same | stub: ok | **refused on chain**: `ERR_OVER_PER_PAYMENT_CAP`, failed tx `FCdztpqKof3QKpFdhqk8pjyg7S1Xo9WvSmBoi9g3o5Gh` | nothing |
| buy | `INV2-P2AZ-RGEV-A58A-UGAU`, USD 84.00 to `sb…@personal.example.com` | ok | **signed**, tx `Bh52ETnYSR2F95Muam1NngTscRLBndNmgBLYiUNx6t6n` | vaulted wallet charged: order **`45369303HX956784Y`**, capture **`3CC314244X496663H`**; paid out to the shop: batch **`YZLPVJRUYQWDS`** (PENDING at submission). Request `pay-360bd0b6-4424-48ec-81da-e612463ee849` |
| swap | sleeves invoice `INV2-DSAH-TRJE-35AC-KXXL`, USD 12.00 to `sb…@personal.example.com` | not run | **signed** (request `chk-cbd0bfa9-80be-4ea1-978d-3233cce9acc2`), tx `dr6UjAKDD9iGrNYpErg27ceQABG7bT9mrrTxhNkD1TD` | sent to the rail with payee `sa…@cardvau1t.example`: **blocked** `PP3_BAD_SIGNATURE`, no PayPal call |
| revoke | | | owner `revoke`: tx `76ArqpgcojoUeiYKcyxsiAyEK9FYpnV2p8c8WGbrMP42`; `get_agent` afterwards: `revoked: true` | owner `/vault/revoke`: the vault token deleted (DELETE 204), PayPal answers **HTTP 404** for it |
| revoke: agent's next request | binder pages `INV2-Y8AA-QGFK-VFX2-NC4Z`, USD 5.00 to `sb…@personal.example.com` | **held**: `unknown payee` | not called | nothing |
| revoke: the swap's signed charge, unchanged | (swap's order) | | | **blocked** `PP3_AGENT_REVOKED`, no PayPal call |
| revoke: owner re-arms the agent | | | `set_mandate` with the setup mandate: **refused on chain**, `ERR_AGENT_REVOKED: grokbot-hank`, failed tx `z6aWR6dazqYfT6gYc2d8p7y8dXGddowdY6SdDoT313D` | |

Rail log for the run (request ids are redacted by the rail):

```
PP3 listening on 127.0.0.1:8789 (vault routes on)
vault grokbot-hank: payment token stored
charging <REDACTED>: USD 84.00 from the vault for sb…@personal.example.com order <REDACTED>
charged <REDACTED>: order 45369303HX956784Y capture 3CC314244X496663H
submitting <REDACTED>: USD 84.00 to sb…@personal.example.com signed at 2026-11-12T13:31:16Z
submitted <REDACTED>: batch YZLPVJRUYQWDS PENDING
blocked checkout <REDACTED>: PP3_BAD_SIGNATURE
vault grokbot-hank: revoked, DELETE 204, GET after 404
blocked checkout <REDACTED>: PP3_AGENT_REVOKED
```

## Checked afterwards

- `8B5wdduq…`, `FCdztpqK…` and `z6aWR6da…` through RPC (`tx` method): **Failure** with `ERR_PAYPAL_PAYEE_NOT_ALLOWED`, `ERR_OVER_PER_PAYMENT_CAP` and `ERR_AGENT_REVOKED`.
- Vault status after the run: `revoked`.

## Notes

- The script's own re-arm step read the mandate with `get_mandate` after the revoke, which answers `null` for a revoked agent, so it sent `mandate: null`: tx `CrWXkimLtBBQyGLNnUgBAH4foFV4Kj14wfgcc2KMBrpk` failed on JSON deserialization, not on the revoke, and the script logged no tx hash (near-cli-rs prints no transaction id on a failed call). The script now reads the mandate before the revoke. The agent could not be un-revoked to rerun, so the same `set_mandate`, with the mandate from the transcript's setup line, was sent once by hand with near-cli-rs as the owner; its line in the transcript is the last one, hash taken from the explorer.
- Revoke deletes the agent's NEAR function-call key, so the agent's own requests after a revoke are rejected by NEAR before the contract runs; there is no on-chain `ERR_AGENT_REVOKED` for them. In this run the agent's next request did not get that far: the scam check held it (`unknown payee`, a model judgment on an allowed merchant). `ERR_AGENT_REVOKED` on chain is shown by the owner's re-arm.
- The transcript's `capture_id` on the buy line reads `3IBAN …663H`: the buyer's redactor took the capture id for an IBAN. The real capture id, `3CC314244X496663H`, is in the rail log and the rail's order record.
- The stubbed beats replace only the scam check, as PP-L1 did.
- Explorer: `https://testnet.nearblocks.io/txns/<hash>`.

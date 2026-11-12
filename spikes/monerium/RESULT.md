# S-b: Monerium link via MPC address — PASS

## Evidence (team sandbox profile, 2026-11-03/04)

The live spike passed on **NEAR testnet + Base Sepolia + Monerium sandbox**, on the
team's own sandbox application and profile (id ending `ab78`).
MPC signer: `nearh-cc1-1793550206.testnet`, path `nearh-sb-monerium`, derived EOA
`0xE0A8bb55759D9565113E125f5f2937Bf2f85e52E`.

| Check | Observed result |
|---|---|
| MPC ownership declaration | EIP-191 recovery matched the derived EOA; `POST /addresses` returned **201** at 2026-11-03 10:52:25 UTC. The profile had no address before; it has exactly this one after |
| IBAN | `POST /ibans` returned **202**; IBAN ending **4141** issued for the EOA on `basesepolia` |
| Sandbox EURe mint | Owner simulated a EUR 100 SEPA payment to the IBAN ending 4141 at sandbox.monerium.dev/receive. Issue order `6668ee04-d891-11f1-a9cb-fa98e9983566`, **processed**; balance API: **100 EURe** at the EOA |
| First payout | **EUR 0.01**, `POST /orders` returned **200** at 2026-11-04 20:52:57 UTC; redeem order `32298aa0-cbd1-425d-9ba5-012295db6b80`, pending, then **processed** |
| Identical signed order submitted again | **400**, Monerium's body: `{"code":400,"status":"Bad Request","message":"Duplicate order"}`. Same payload object, no client-supplied order UUID |
| Final balance | **100 EURe**: the payout recipient was the profile's own sandbox IBAN (…4141), so Monerium issued the 0.01 back (issue order `9ea34945-5dbe-4fc8-a969-e8e1ee730178`, processed) |

Monerium's `code` field is the HTTP status, not a distinct error code; the stable
value to match on is `message: "Duplicate order"` with status 400.

Transactions:

- [Ownership declaration, NEAR testnet](https://testnet.nearblocks.io/txns/4p5Kn6LaF5WD7hL972jisKS8uSrnG7YZ59wTSh34QTXs)
- [Payout signature, NEAR testnet](https://testnet.nearblocks.io/txns/ANLwCeMGQ2A4Mx8qQgBNe5pRH3Nq9nwDMZkpCgz12ox4)
- [Mint, Base Sepolia](https://base-sepolia.blockscout.com/tx/0x10782d1e4f3fe78795c609edd3a28acce01dcaa7f97cbbf1a0198fcc91e63a06)
- [Processed payout, Base Sepolia](https://base-sepolia.blockscout.com/tx/0x3b9ffba3a95510805cd716c2b947cf0fcbffbfd103a468864bd4fad0543d02e3)
- [0.01 issued back, Base Sepolia](https://base-sepolia.blockscout.com/tx/0xbd3626ec0bab7dc00c4a808ea1ffdb15a8ce132066f3ee77b303ab58d761379e)

Order states and EVM hashes were read from the authenticated Monerium orders API.
This is a sandbox run, not a real bank settlement. Credentials, tokens, signatures,
raw partner responses and IBANs are withheld.

## Evidence files

`evidence.ndjson` is the published record of the run above. Runner lines were
copied from the run journal unchanged. Lines the runner did not write
(`mint_verified`, `payout_processed`, `payout_returned`) were read from the Monerium
API by hand and carry `"manual":true` and a `"note"` saying so; a test fails if a
non-runner line lacks that mark. The runner never reads or writes this file.

Each run appends to `evidence.local.ndjson`, which is gitignored. Before this
payout run the journal held no `payout_attempt`, so the guard did not block and
nothing was cleared.

## Message compatibility confirmed live

- Link: `I hereby declare that I am the address owner.`
- Payout: `Send EUR {canonical amount} to {sandbox IBAN} at {UTC RFC3339}`.
- Accepted, IBAN redacted: `Send EUR 0.01 to <SANDBOX_IBAN> at 2026-11-04T20:52:44Z`.
- Confirms the contract interface's second-resolution UTC format
  (`YYYY-MM-DDTHH:MM:SSZ`), canonical amount `0.01`, IBAN without spaces. Other
  amount strings and timestamp edge cases were not probed live.

## Reproduce

Requires Node >=22, pnpm, an own funded NEAR testnet account with its key file at
`~/.near-credentials/testnet/<account>.json` (near-cli-rs files without
`account_id` are accepted), and a **Private** Monerium sandbox application
(<https://sandbox.monerium.dev/developers>). Credentials default to
`rails/monerium/.env`; point `MONERIUM_ENV_FILE` at another local file to keep them
outside the checkout. Never paste a secret or signing key into chat.

```dotenv
MONERIUM_ENVIRONMENT=sandbox
MONERIUM_CLIENT_ID=
MONERIUM_CLIENT_SECRET=
MONERIUM_PROFILE_ID=      # optional: a profile UUID; empty = default profile
MONERIUM_SANDBOX_IBAN=    # a sandbox recipient, never real bank details
```

```sh
cd spikes/monerium
pnpm install --ignore-workspace --frozen-lockfile
export NEAR_ACCOUNT_ID=<your>.testnet
node spike.mjs check    # auth, derive EOA, list addresses; changes nothing
node spike.mjs link     # MPC-sign the declaration, POST /addresses (201 linked, 202 pending)
node spike.mjs iban     # POST /ibans for the EOA on basesepolia, if the profile has none
# Human step: simulate an incoming SEPA payment to that IBAN at sandbox.monerium.dev/receive
node spike.mjs payout   # payout + duplicate replay
node --test spike.test.mjs
```

`payout` defaults to EUR 0.01 and refuses more than EUR 1. It checks the sandbox
balance before signing. **A successful run always sends the replay POST, by
design:** after the first order is accepted it submits the identical payload once
more (no new timestamp, signature or order UUID), so an order-ID conflict cannot
pass for signature replay protection. It classifies the second response as
duplicate refusal, idempotent return of the same order, a new accepted order, or
inconclusive, and exits non-zero unless it is a duplicate refusal. Acceptance does
not prove settlement; check the order state separately.

### Rerun guard

Two checks stop a second payout run, even if the first response was lost:

1. The journal check: a `payout_attempt` line in `evidence.local.ndjson` blocks
   the run before signing.
2. An exclusive-create lock: just before the first `POST /orders` the runner
   creates `evidence.local.payout.lock` with `O_EXCL` (`wx`) and never removes it.
   Two runners started together can both pass the journal check, but only one can
   create the lock; the other stops before submitting.

Both files are gitignored. To run a fresh experiment, inspect the sandbox orders
first, then archive both files deliberately. Never blindly retry an unknown
outcome. To publish a run, copy lines from the journal into `evidence.ndjson` after
checking them for secrets, and mark any line you add by hand `"manual":true`.

## Fallback and next action

No Safe fallback is needed: MPC linking and the sandbox payout passed. C6 can use
the accepted format above; O2 and M1 can proceed against the confirmed endpoints and
match a duplicate on status 400 with `message: "Duplicate order"`. M1 must still
deduplicate its own `request_id` values and enforce short validity windows: one
exact replay refusal does not prove every replay variant is rejected. No mainnet,
real funds, production Monerium or real bank settlement was tested.

## Sources

- Zold-app's Monerium client and its amount and payout formatter (private code, not linked)
- [Monerium Private app authentication and linking](https://docs.monerium.com/private/)
- [Monerium sandbox funding](https://docs.monerium.com/sandbox/)
- [Monerium API and OpenAPI specification](https://docs.monerium.com/api/)

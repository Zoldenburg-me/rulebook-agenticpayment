# Owner Monerium link (O2)

`pnpm link-agent <agent>` links an agent's MPC-derived EOA to the team's Monerium **sandbox** profile on Base Sepolia:

1. Reads `get_agent`: the agent must exist, not be revoked, and have an `evm_address`.
2. Asks Monerium (`GET /addresses`) whether that EOA is already on the profile for `basesepolia`. If so it stops and sends nothing.
3. Otherwise it reuses a `signed` owner link reservation from `list_requests` if the contract has one (a second `link_agent` would fail with `ERR_ALREADY_LINKED`). Without one it calls `link_agent(agent)` as an owner call, using the O1 plumbing (`scripts/owner/near/src/owner.ts`: software P-256 assertion over `owner_nonce + 1`, submitted by `SUBMITTER_ACCOUNT_ID`, 300 Tgas). It waits until `owner_nonce` is consumed, then polls for the new reservation to leave `pending`. If `link_agent` is already in flight (`linked: true`, reservation `pending`), it waits for that one instead.
4. Checks that the reservation digest is the EIP-191 hash of `I hereby declare that I am the address owner.` and that the signature recovers to the agent EOA. Then it POSTs `{ profile, address, chain: "basesepolia", message, signature }` to `/addresses`.
5. **201** means linked and **202** means pending verification; any other 2xx is an error. A 4xx comes back as `MoneriumError` carrying Monerium's `code` and `message`, with hex, UUIDs and IBANs redacted. If Monerium refuses with a 4xx but now lists the address (a parallel run), the result is `already_linked`.

If the MPC callback failed, the reservation ends `unknown` and the contract resets `linked`. The script says so; run it again.

The Monerium client (`src/monerium.ts`) is ported from `spikes/monerium` (S-b). It uses client credentials against `https://api.monerium.dev` only, with the environment fixed to sandbox and the chain to Base Sepolia. The token never leaves that host, and errors never include the token, the secret or a raw response body.

## Setup

Use the NEAR variables from `scripts/owner/near` (see `.env.example`) and an owner key in `$OWNER_KEY_DIR`. The Monerium credentials are read from `MONERIUM_ENV_FILE` (default `~/.config/nearh/monerium-sandbox.env`, outside the repo) and are never printed.

```sh
cd scripts/owner/monerium
export CONTRACT_ID=<contract>.testnet SUBMITTER_ACCOUNT_ID=<submitter>.testnet
pnpm link-agent agent-1
```

## Tests

`pnpm test` runs `test/link.test.ts`. NEAR RPC is mocked by stubbing `fetch` under O1's `view`, the owner call is stubbed, and the Monerium sandbox gets its own mocked `fetch`. The link signatures are real secp256k1 signatures. Covered:
- fresh link (checks the `link_agent` args, borsh and gas, and the POST body)
- 201 linked, 202 pending verification, other 2xx refused
- a 4xx surfaced with its code and message, redacted
- already linked on Monerium; another profile or chain does not count
- already linked on the contract: the signature is reused and `link_agent` is not called
- a 4xx while the address is already listed
- a signature that does not recover to the EOA, or a wrong digest: nothing is posted
- non-link or agent-caller reservations are ignored
- callback failed (`unknown`), still pending, in-flight wait
- revoked, unknown or EOA-less agent
- `link_agent` that never lands
- profile selection, auth refusal, the sandbox-only guards, and redaction

## Live run (2026-11-04, NEAR testnet + Monerium sandbox)

Run against the R1 test contract `r1live.nearh-cc1-1793550206.testnet` (relayer/LIVE.md), with agent `agent-1` and the O1 test owner key. The submitter was `r1relayer.nearh-cc1-1793550206.testnet`, and the profile is the team sandbox profile (id ending `ab78`).

| Step | Result |
|---|---|
| `link_agent agent-1`, owner nonce 7 | [`D8EHcE6W7KJfgP71Z6qq9Wz6Euu6qHt7tJMUvEh8DqdL`](https://testnet.nearblocks.io/txns/D8EHcE6W7KJfgP71Z6qq9Wz6Euu6qHt7tJMUvEh8DqdL); reservation `link-1793828368879` `signed`, recovers to `0x4b05d2f98ff1be125a4c9f99a12a39f50c699d15` |
| `POST /addresses` | **201**, `{"result":"linked","address":"0x4b05…9d15","status":201}` |
| Rerun | `already_linked`; nothing sent to NEAR or Monerium |

Tokens, credentials, the signature and raw Monerium bodies are withheld. No IBAN was requested.

# PP4: `pay_paypal` live run — NOT RUN (blocked by missing env)

No end-to-end run (testnet contract + sandbox PP3) was made for this PR. Offline tests cover the flow (`test/paypal.test.ts`); PP3's own live sandbox payout is in `rails/paypal/RESULT.md` (NEAR stubbed there).

## What is missing, exactly

| Needed | State on 2026-11-09 | Owner of the step |
|---|---|---|
| A testnet mandate contract with shape 4 (PP2) deployed | none known: PP3's RESULT.md also ran with NEAR stubbed for this reason | lead / owner deploy |
| `set_mandate` for the agent with a `paypal` rail (amount range, budget, period) | not set; owner-side, passkey-signed | owner (`scripts/owner/`, dashboard) |
| The supplier's PayPal payee on the agent's payees (`Payee::Paypal { receiver }`, the personal sandbox account) | not set; owner-side | owner |
| `agent/mcp/.env`: `MANDATE_CONTRACT_ID`, `AGENT_NEAR_PRIVATE_KEY` (the agent's function-call key on that contract), `AGENT_EVM_ADDRESS` | file absent | agent operator |
| `NEAR_AI_API_KEY` (agent/mcp env or `~/.config/nearh/nearai.env`) | absent; without it `pay_paypal` blocks with `ERR_SCAM_CHECK_UNAVAILABLE` by design | lead |
| PP3 running (`cd rails/paypal && CONTRACT_ID=<contract> PP3_AGENT_TOKENS=<agent>=<token> pnpm start`) and the same token as `PP3_AGENT_TOKEN` in `agent/mcp/.env` | not running; sandbox credentials exist in `~/.config/nearh/paypal-sandbox.env` (PP3 only) | rail operator |
| A sent sandbox invoice from the supplier (`cd supplier && node src/cli.ts create ...`) | can be made any time with the same credentials file | supplier |

## Run, once the above exists

```sh
cd supplier && node src/cli.ts create --amount 1.00 --description "Weather data API access" --due 2026-11-20 > /tmp/invoice.json
pnpm --filter @nearh/agent-mcp pay-paypal --invoice /tmp/invoice.json
```

Expected: `{"status":"paid","request_id":"pay-…","amount":"1.00","pay_to":"sb…@personal.example.com","payout_batch_id":"…","scam_check":"ok"}`. Record it here with the payee masked and no token, key or full email.

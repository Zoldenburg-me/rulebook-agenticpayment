// pnpm submit <agent> <request_id> <iban> <amount> <memo>: one payout through M1, without the service.
import { deps } from "../config.ts";
import { submitPayout } from "../payout.ts";

const [agent, request_id, iban, amount, memo = ""] = process.argv.slice(2);
const result = await submitPayout(deps(), { agent, request_id, iban, amount, memo });
console.log(JSON.stringify(result));
if (result.status !== "submitted") process.exitCode = 1;

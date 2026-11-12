// pnpm submit '<order JSON>': one PaypalOrder through PP3, without the service.
import { deps } from "../config.ts";
import { submitPaypalPayout } from "../payout.ts";

const result = await submitPaypalPayout(deps(), JSON.parse(process.argv[2] ?? "null"));
console.log(JSON.stringify(result));
if (result.status !== "submitted") process.exitCode = 1;

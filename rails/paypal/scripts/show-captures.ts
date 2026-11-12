// PP-T1: what PayPal itself says about some sandbox captures, after a run: captured, refunded, left.
//   node scripts/show-captures.ts <capture_id> ...
import { credentialsFile, readCredentials } from "../src/config.ts";
import { sandboxClient } from "../src/paypal.ts";
import { CAPTURE_ID, refundable } from "../src/refund.ts";

const usd = (c: bigint) => `${c / 100n}.${String(c % 100n).padStart(2, "0")}`;
const paypal = sandboxClient(readCredentials(credentialsFile()));
await paypal.authenticate();
for (const id of process.argv.slice(2)) {
  if (!CAPTURE_ID.test(id)) throw new Error(`not a capture id: ${id}`);
  const r = await refundable(paypal, id);
  console.log(r.ok ? `${id} captured ${usd(r.captured)} refunded ${usd(r.refunded)} left ${usd(r.left)}` : `${id} ${r.error_code}: ${r.detail}`);
}

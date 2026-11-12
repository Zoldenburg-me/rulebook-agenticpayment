// PP-W1: subscribes a public HTTPS URL to the settlement event types on the sandbox app, or lists/deletes
// subscriptions. Prints ids and URLs only, never a credential.
//   node scripts/register-webhook.ts create https://<host>/paypal/webhook
//   node scripts/register-webhook.ts list
//   node scripts/register-webhook.ts delete <webhook_id>
import { credentialsFile, readCredentials } from "../src/config.ts";
import { sandboxClient } from "../src/paypal.ts";
import { EVENT_STATUS } from "../src/webhook.ts";

const [cmd, arg] = process.argv.slice(2);
const client = sandboxClient(readCredentials(credentialsFile()));
await client.authenticate();
if (cmd === "create") {
  if (!arg?.startsWith("https://")) throw new Error("create needs an https URL");
  const a = await client.request("POST", "/v1/notifications/webhooks", { url: arg, event_types: Object.keys(EVENT_STATUS).map((name) => ({ name })) });
  console.log(a.status, a.ok ? { id: a.body.id, url: a.body.url, event_types: a.body.event_types?.length } : { name: a.body?.name, details: a.body?.details, debug_id: a.debugId });
} else if (cmd === "list") {
  const a = await client.request("GET", "/v1/notifications/webhooks");
  console.log(a.status, (a.body?.webhooks ?? []).map((w: any) => ({ id: w.id, url: w.url })));
} else if (cmd === "delete") {
  const a = await client.request("DELETE", `/v1/notifications/webhooks/${encodeURIComponent(arg)}`);
  console.log(a.status);
} else {
  throw new Error("usage: create <url> | list | delete <id>");
}

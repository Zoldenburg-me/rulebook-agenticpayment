// Demo supplier CLI. Prints the buyer view of an invoice as JSON on stdout; errors go to stderr
// without credentials.
//
//   node src/cli.ts create --amount 25.00 --description "..." --due 2026-11-20 [--service NAME] [--payee EMAIL] [--bill-to EMAIL] [--draft]
//   node src/cli.ts get INV2-XXXX-XXXX-XXXX-XXXX
//
// Credentials: PAYPAL_ENV_FILE, else ~/.config/nearh/paypal-sandbox.env, parsed into a private
// object (never into process.env). --payee (the supplier's PayPal email, which the buyer pays)
// defaults to PAYPAL_SANDBOX_RECEIVER_EMAIL from that file, the personal sandbox account; --bill-to
// defaults to buyer@example.com (the sandbox does not deliver mail outside PayPal).

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, parseEnv } from "node:util";
import { getInvoice, issueInvoice } from "./invoice.ts";
import { sandboxClient, type Credentials } from "./paypal.ts";

export function credentialsFile(env: NodeJS.ProcessEnv = process.env): string {
  return env.PAYPAL_ENV_FILE || join(homedir(), ".config", "nearh", "paypal-sandbox.env");
}

export function readCredentials(file: string): Credentials {
  try {
    return { ...parseEnv(readFileSync(file, "utf8")) };
  } catch {
    throw new Error("cannot read the PayPal credentials file (PAYPAL_ENV_FILE)");
  }
}

async function main(argv: string[]): Promise<void> {
  const { positionals, values } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      amount: { type: "string" },
      description: { type: "string" },
      due: { type: "string" },
      service: { type: "string" },
      payee: { type: "string" },
      "bill-to": { type: "string", default: "buyer@example.com" },
      draft: { type: "boolean", default: false },
    },
  });
  const [cmd, id] = positionals;
  const creds = readCredentials(credentialsFile());
  const client = sandboxClient(creds);
  if (cmd === "get" && id) {
    console.log(JSON.stringify(await getInvoice(client, id), null, 2));
  } else if (cmd === "create") {
    const payee = values.payee ?? creds.PAYPAL_SANDBOX_RECEIVER_EMAIL;
    if (!values.amount || !values.description || !values.due || !payee) {
      throw new Error("create needs --amount, --description, --due and --payee (or PAYPAL_SANDBOX_RECEIVER_EMAIL)");
    }
    const inv = await issueInvoice(
      client,
      { amount: values.amount, description: values.description, dueDate: values.due, service: values.service, payee, billTo: values["bill-to"] },
      { send: !values.draft },
    );
    console.log(JSON.stringify(inv, null, 2));
  } else {
    throw new Error("usage: cli.ts create --amount 25.00 --description TEXT --due YYYY-MM-DD | cli.ts get INVOICE_ID");
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err: Error) => {
    console.error(`supplier: ${err.message}`);
    process.exit(1);
  });
}

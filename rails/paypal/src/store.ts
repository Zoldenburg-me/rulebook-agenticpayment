// One record per (agent, request_id): PP3 claims it before the PayPal POST and deletes it only on a 429,
// so a signed order is submitted at most once, even across restarts or two PP3 processes. PayPal
// refuses a reused sender_batch_id but pays the same item again under a new one (PP-S1), so this
// store, not PayPal, is what stops a second payout.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export type OrderState =
  /** Claimed, POST not answered yet. Left like this after a crash: outcome unknown, never retried. */
  | "submitting"
  /** PayPal accepted the batch; `payout_batch_id` is set. */
  | "submitted"
  /** PayPal answered 400 with `SENDER_BATCH_ID` already used. */
  | "duplicate_batch"
  /** Any other PayPal refusal. */
  | "refused"
  /** In transit, 5xx, or a 2xx without a batch id or for another sender_batch_id: check the sandbox by hand. */
  | "unknown";

/** No full payee, no signature, no credentials: the payee is kept masked. */
export type OrderRecord = {
  agent: string;
  request_id: string;
  state: OrderState;
  payee_masked: string;
  amount: string;
  at: string;
  payout_batch_id?: string;
  batch_status?: string;
  http_status?: number;
  debug_id?: string;
  detail?: string;
};

export type Store = {
  get(agent: string, requestId: string): OrderRecord | undefined;
  /** Creates the record; false if one already exists for (agent, request_id). Atomic. */
  claim(record: OrderRecord): boolean;
  /** Replaces an existing record. */
  update(record: OrderRecord): void;
  /** Deletes the record, so the request can be claimed again. Only for a POST PayPal rate-limited (429). */
  release(agent: string, requestId: string): void;
};

/** In-process store (tests, or a single short-lived run). */
export function memoryStore(): Store & { records: Map<string, OrderRecord> } {
  const records = new Map<string, OrderRecord>();
  const id = (agent: string, requestId: string) => `${agent}\n${requestId}`;
  return {
    records,
    get: (agent, requestId) => records.get(id(agent, requestId)),
    claim(record) {
      const k = id(record.agent, record.request_id);
      if (records.has(k)) return false;
      records.set(k, record);
      return true;
    },
    update(record) {
      records.set(id(record.agent, record.request_id), record);
    },
    release(agent, requestId) {
      records.delete(id(agent, requestId));
    },
  };
}

/** One JSON file per (agent, request_id) in `dir`, created with O_EXCL (`wx`) so only one claim wins. */
export function fileStore(dir: string): Store {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = (agent: string, requestId: string) =>
    join(dir, `${createHash("sha256").update(`${agent}\n${requestId}`).digest("hex")}.json`);
  return {
    get(agent, requestId) {
      try {
        return JSON.parse(readFileSync(path(agent, requestId), "utf8"));
      } catch (e: any) {
        if (e?.code === "ENOENT") return undefined;
        throw new Error(`cannot read the order record for ${requestId}; refusing to submit`);
      }
    },
    claim(record) {
      try {
        writeFileSync(path(record.agent, record.request_id), JSON.stringify(record), { flag: "wx", mode: 0o600 });
        return true;
      } catch (e: any) {
        if (e?.code === "EEXIST") return false;
        throw e;
      }
    },
    update(record) {
      const p = path(record.agent, record.request_id);
      writeFileSync(`${p}.tmp`, JSON.stringify(record), { mode: 0o600 });
      renameSync(`${p}.tmp`, p);
    },
    release(agent, requestId) {
      unlinkSync(path(agent, requestId));
    },
  };
}

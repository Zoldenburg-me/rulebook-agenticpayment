// One record per (agent, request_id): M1 claims it before the Monerium POST and never deletes it,
// so a signed order is submitted at most once, even across restarts or two M1 processes.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export type OrderState =
  /** Claimed, POST not answered yet. Left like this after a crash: outcome unknown, never retried. */
  | "submitting"
  /** Monerium accepted it; `monerium_order_id` is set. */
  | "submitted"
  /** Monerium answered 400 "Duplicate order". */
  | "duplicate_order"
  /** Any other Monerium refusal. */
  | "refused"
  /** In transit, 5xx or a 2xx without an order id: check the sandbox by hand. */
  | "unknown";

/** No full IBAN, no signature, no credentials: the IBAN is kept as its last 4 characters. */
export type OrderRecord = {
  agent: string;
  request_id: string;
  state: OrderState;
  iban_last4: string;
  amount: string;
  at: string;
  monerium_order_id?: string;
  monerium_state?: string;
  http_status?: number;
  detail?: string;
};

export type Store = {
  get(agent: string, requestId: string): OrderRecord | undefined;
  /** Creates the record; false if one already exists for (agent, request_id). Atomic. */
  claim(record: OrderRecord): boolean;
  /** Replaces an existing record. */
  update(record: OrderRecord): void;
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
  };
}

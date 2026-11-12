// Each relayed item is sent at most once. An id is claimed before its tx goes out and is never
// released, even on error: a tx that may have been broadcast is checked by hand, not resent.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

export interface Journal {
  /** Throws if `id` was claimed before; otherwise records it. */
  claim(id: string): void;
}

export class MemoryJournal implements Journal {
  readonly ids = new Set<string>();
  claim(id: string): void {
    if (this.ids.has(id)) throw new Error(`already relayed: ${id}`);
    this.ids.add(id);
  }
}

/**
 * One file per id in a local directory (mode 700, files 600), so a restart does not resend.
 * Each claim is an exclusive create, so two processes cannot both claim the same id.
 */
export class FileJournal implements Journal {
  private readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
  }
  claim(id: string): void {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const file = join(this.dir, bytesToHex(sha256(utf8ToBytes(id))));
    try {
      writeFileSync(file, id + "\n", { mode: 0o600, flag: "wx" });
    } catch (e: any) {
      if (e?.code === "EEXIST") throw new Error(`already relayed: ${id} (see ${file})`);
      throw e;
    }
  }
}

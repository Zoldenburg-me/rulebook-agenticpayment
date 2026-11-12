// near-cli-rs output is redacted before it is printed: no NEAR key, public or secret, survives.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { base58Encode } from "../src/base58.ts";
import { redact } from "../src/near.ts";

test("ed25519 and secp256k1 keys of every real length are redacted", () => {
  const edSeed = ed25519.utils.randomSecretKey();
  const edPub = ed25519.getPublicKey(edSeed);
  const secSecret = secp256k1.utils.randomSecretKey();
  const secPub = secp256k1.getPublicKey(secSecret, false).slice(1); // NEAR drops the 0x04 prefix.
  const keys = [
    `ed25519:${base58Encode(edPub)}`, // ~43-44 chars
    `ed25519:${base58Encode(new Uint8Array([...edSeed, ...edPub]))}`, // ~87-88 chars
    `ed25519:${base58Encode(new Uint8Array(32))}`, // all-zero: the shortest 32-byte encoding, 32 chars
    `secp256k1:${base58Encode(secPub)}`,
    `secp256k1:${base58Encode(secSecret)}`,
  ];
  assert.ok(keys[0].length - 8 <= 44 && keys[0].length - 8 >= 43, "ed25519 public key length out of range");
  // Failure messages name the key index only, never the key or the output (no key material in logs).
  keys.forEach((key, i) => {
    const body = key.slice(key.indexOf(":") + 1);
    const out = redact(`Public key: ${key}\naccess key ${key} added (${key})`);
    assert.ok(!out.includes(body), `key #${i} left unredacted`);
    const curve = key.split(":")[0];
    assert.ok(
      out.split("\n")[1] === `access key ${curve}:<redacted> added (${curve}:<redacted>)`,
      `key #${i} redacted in the wrong shape`,
    );
  });
});

test("redaction keeps the tx hash and drops seed/private lines", () => {
  const hash = base58Encode(new Uint8Array(32).fill(7));
  const out = redact(`Transaction ID: ${hash}\nSeed phrase: alpha beta\nprivate_key: x\ndone`);
  assert.equal(out, `Transaction ID: ${hash}\ndone`);
});

test("prefixed, upper-case and URL-encoded keys are redacted", () => {
  const body = base58Encode(ed25519.getPublicKey(ed25519.utils.randomSecretKey()));
  const cases: [string, string][] = [
    [`\x1b[32med25519:${body}\x1b[0m`, "\x1b[32med25519:<redacted>\x1b[0m"], // ANSI colour ends in `m`
    [`pk_ed25519:${body}`, "pk_ed25519:<redacted>"],
    [`ED25519:${body}`, "ED25519:<redacted>"],
    [`?key=ed25519%3A${body}`, "?key=ed25519%3A<redacted>"],
    [`secp256k1%3a${body}`, "secp256k1%3a<redacted>"],
  ];
  cases.forEach(([input, want], i) => {
    const out = redact(input);
    assert.ok(!out.includes(body), `case #${i} left unredacted`);
    assert.ok(out === want, `case #${i} redacted in the wrong shape`);
  });
});

// Agent EOA derivation against spike S-a's recorded run (spikes/chainsig/RESULT.md):
// predecessor nearh-cc1-1793550206.testnet, path nearh-sa-test on v1.signer-prod.testnet,
// whose MPC signature recovered to that address. Root key: the MPC's `public_key` view.
import assert from "node:assert/strict";
import { test } from "node:test";
import { deriveEvmAddress } from "../src/derive.ts";

const ROOT = "secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3";

test("derives the S-a address, lowercase", () => {
  assert.equal(
    deriveEvmAddress(ROOT, "nearh-cc1-1793550206.testnet", "nearh-sa-test"),
    "0xbbc0320e02d371a71f18a40b7b15404df218d880",
  );
});

test("a different path or predecessor gives a different address", () => {
  const a = deriveEvmAddress(ROOT, "nearh-cc1-1793550206.testnet", "nearh-sa-test");
  assert.notEqual(deriveEvmAddress(ROOT, "nearh-cc1-1793550206.testnet", "agent-b"), a);
  assert.notEqual(deriveEvmAddress(ROOT, "other.testnet", "nearh-sa-test"), a);
});

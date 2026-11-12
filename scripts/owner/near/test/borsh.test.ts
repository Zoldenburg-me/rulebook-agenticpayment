// Borsh of each owner method's argument tuple, byte-equal to `borsh::to_vec` in the contract
// crate (types from contract/src/types.rs, values from contract/tests/c2_owner.rs fixtures).
import assert from "node:assert/strict";
import { test } from "node:test";
import { bytesToHex } from "@noble/hashes/utils.js";
import { base58Decode, base58Encode } from "../src/base58.ts";
import { addAgentArgs, agentArgs, payeeArgs, setMandateArgs, setRelayerArgs, Writer, type Mandate } from "../src/borsh.ts";

const KEY_1 = `ed25519:${base58Encode(new Uint8Array(32).fill(1))}`;
const SWEEP = {
  safe_address: "0x5afe000000000000000000000000000000000001",
  usdc_address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
  eure_address: "0x29f37f6adca168b79b8d9567eab9be3fbf21db85",
  chain_id: 84532,
};
const rail = (max: string, budget: string) => ({ amount_range: { min: "1", max }, budget, period_secs: 604_800 });
const MANDATE: Mandate = {
  x402: rail("1000000", "20000000"),
  sepa: rail("50000000000000000000", "200000000000000000000"),
  usdc_address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
  eure_address: "0x29f37f6adca168b79b8d9567eab9be3fbf21db85",
  chain_id: 84532,
  float_cap: { usdc: "25000000", eure: "250000000000000000000" },
  max_validity_secs: 300,
};

test("add_agent args", () => {
  assert.equal(
    bytesToHex(addAgentArgs("agent-a", KEY_1, SWEEP, "0xabcdef0123456789abcdef0123456789abcdef01")),
    "070000006167656e742d61210000000001010101010101010101010101010101010101010101010101010101010101012a0000003078356166653030303030303030303030303030303030303030303030303030303030303030303030312a0000003078303336636264353338343263353432363633346537393239353431656332333138663364636637652a000000307832396633376636616463613136386237396238643935363765616239626533666266323164623835344a0100000000002a000000307861626364656630313233343536373839616263646566303132333435363738396162636465663031",
  );
});

test("set_relayer args, Some and None", () => {
  assert.equal(bytesToHex(setRelayerArgs("relayer-demo.testnet")), "011400000072656c617965722d64656d6f2e746573746e6574");
  assert.equal(bytesToHex(setRelayerArgs(null)), "00");
});

test("set_mandate args", () => {
  assert.equal(
    bytesToHex(setMandateArgs("agent-a", MANDATE)),
    "070000006167656e742d610100000000000000000000000000000040420f00000000000000000000000000002d3101000000000000000000000000803a09000000000001000000000000000000000000000000000088b116afe3b50200000000000000000020c65abc8ed70a00000000000000803a0900000000002a0000003078303336636264353338343263353432363633346537393239353431656332333138663364636637652a000000307832396633376636616463613136386237396238643935363765616239626533666266323164623835344a01000000000040787d010000000000000000000000000000a877716b728d0d000000000000002c010000",
  );
});

test("add_payee args, x402 and sepa", () => {
  assert.equal(
    bytesToHex(payeeArgs("agent-a", { rail: "x402", pay_to: "0x5afe000000000000000000000000000000000002" })),
    "070000006167656e742d61002a000000307835616665303030303030303030303030303030303030303030303030303030303030303030303032",
  );
  assert.equal(
    bytesToHex(payeeArgs("agent-a", { rail: "sepa", iban: "DE89370400440532013000" })),
    "070000006167656e742d61011600000044453839333730343030343430353332303133303030",
  );
});

test("revoke args", () => {
  assert.equal(bytesToHex(agentArgs("agent-a")), "070000006167656e742d61");
});

test("out-of-range and unsupported values are refused, not truncated", () => {
  assert.throws(() => new Writer().u64(2n ** 64n), /out of range/);
  assert.throws(() => new Writer().u128(-1), /out of range/);
  assert.throws(() => new Writer().u32(2 ** 32), /out of range/);
  assert.throws(() => new Writer().publicKey("secp256k1:abc"), /only ed25519/);
  assert.throws(() => payeeArgs("a", { rail: "card" } as any), /unknown payee rail/);
});

test("base58 round trip keeps leading zeros", () => {
  const b = Uint8Array.of(0, 0, 1, 2, 255);
  assert.deepEqual(base58Decode(base58Encode(b)), b);
});

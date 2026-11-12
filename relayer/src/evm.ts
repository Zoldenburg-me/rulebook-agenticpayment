// Base Sepolia: the hashes the contract builds (shape 1), signature recovery, and the relayer's
// own EIP-1559 txs. Mirrors contract/src/shapes/sweep.rs and shapes/mod.rs.

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { sleep, type Rpc } from "./rpc.ts";

export const BASE_SEPOLIA_CHAIN_ID = 84532;
/** contract/src/types.rs MAX_SWEEP_GAS_LIMIT. */
export const MAX_SWEEP_GAS_LIMIT = 150_000n;
/** contract/src/shapes/sweep.rs MAX_SWEEP_FEE_PER_GAS (100 gwei). */
export const MAX_SWEEP_FEE_PER_GAS = 100_000_000_000n;
/** OP-stack predeploy on Base: `getL1Fee(bytes)` quotes the L1 data fee a tx pays on top of its L2 gas. */
export const GAS_PRICE_ORACLE = "0x420000000000000000000000000000000000000F";
/** The most L1 data fee the relayer adds to a EURe gas top-up (0.001 ETH); a raw ERC-20 transfer pays about 1e-8 ETH. */
export const MAX_L1_FEE = 1_000_000_000_000_000n;
/** contract/src/shapes/x402.rs: the USDC EIP-712 domain on Base Sepolia. */
const USDC_EIP712_NAME = "USDC";
const USDC_EIP712_VERSION = "2";
const TRANSFER_SELECTOR = "a9059cbb";
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

export type Hex = string;
export type MpcSignature = { r: Hex; s: Hex; v: number };

/** `payload` of a USDC sweep reservation (docs/interfaces.md §4, `kind: "eip3009"`). */
export type Eip3009Payload = {
  kind: "eip3009";
  asset: string;
  chain_id: number;
  from: string;
  to: string;
  value: string;
  valid_after: number;
  valid_before: number;
  nonce: Hex;
};

/** `payload` of a EURe sweep reservation (`kind: "eip1559_tx"`): the unsigned tx. */
export type Eip1559Payload = {
  kind: "eip1559_tx";
  chain_id: number;
  nonce: number;
  max_priority_fee_per_gas: string;
  max_fee_per_gas: string;
  gas_limit: number;
  to: string;
  value: string;
  data: Hex;
};

const strip0x = (h: string) => h.replace(/^0x/i, "");
export const hex = (b: Uint8Array): Hex => "0x" + bytesToHex(b);
export const unhex = (h: string): Uint8Array => hexToBytes(strip0x(h));
export const keccak = (b: Uint8Array) => keccak_256(b);
export const eqAddr = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

export function assertAddress(field: string, a: unknown): string {
  if (typeof a !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(a)) throw new Error(`${field} must be a 0x address, got ${JSON.stringify(a)}`);
  return a.toLowerCase();
}

/** A 32-byte big-endian word. */
function word(v: bigint | number | string): Uint8Array {
  const n = BigInt(v);
  if (n < 0n || n >= 1n << 256n) throw new Error(`uint256 out of range: ${v}`);
  return unhex(n.toString(16).padStart(64, "0"));
}

const addressWord = (a: string) => unhex(strip0x(assertAddress("address", a)).padStart(64, "0"));

function bytes32(h: string): Uint8Array {
  if (!/^0x[0-9a-fA-F]{64}$/.test(h)) throw new Error(`not a bytes32: ${h}`);
  return unhex(h);
}

// ---- EIP-712 / EIP-3009 ----

const DOMAIN_TYPEHASH = keccak(utf8ToBytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
const TWA_TYPEHASH = keccak(
  utf8ToBytes("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"),
);

/** The EIP-712 digest the MPC signs for a USDC `transferWithAuthorization`. */
export function eip3009Digest(p: Eip3009Payload): Uint8Array {
  const domain = keccak(
    concatBytes(DOMAIN_TYPEHASH, keccak(utf8ToBytes(USDC_EIP712_NAME)), keccak(utf8ToBytes(USDC_EIP712_VERSION)), word(p.chain_id), addressWord(p.asset)),
  );
  const struct = keccak(
    concatBytes(TWA_TYPEHASH, addressWord(p.from), addressWord(p.to), word(p.value), word(p.valid_after), word(p.valid_before), bytes32(p.nonce)),
  );
  return keccak(concatBytes(Uint8Array.of(0x19, 0x01), domain, struct));
}

const selector = (sig: string) => bytesToHex(keccak(utf8ToBytes(sig)).slice(0, 4));

/** USDC `transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, v, r, s)`. */
export function transferWithAuthorizationData(p: Eip3009Payload, sig: MpcSignature): Hex {
  const sel = selector("transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)");
  return hex(
    concatBytes(
      unhex(sel),
      addressWord(p.from),
      addressWord(p.to),
      word(p.value),
      word(p.valid_after),
      word(p.valid_before),
      bytes32(p.nonce),
      word(sig.v),
      bytes32(sig.r),
      bytes32(sig.s),
    ),
  );
}

/** `authorizationState(authorizer, nonce)` calldata: true once the nonce is used. */
export function authorizationStateData(from: string, nonce: Hex): Hex {
  return hex(concatBytes(unhex(selector("authorizationState(address,bytes32)")), addressWord(from), bytes32(nonce)));
}

/** ERC-20 `balanceOf(owner)` calldata. */
export function balanceOfData(owner: string): Hex {
  return hex(concatBytes(unhex(selector("balanceOf(address)")), addressWord(owner)));
}

/** ERC-20 `transfer(to, amount)` calldata, as the contract builds it for the EURe sweep. */
export function erc20TransferData(to: string, amount: bigint): Hex {
  return hex(concatBytes(unhex(TRANSFER_SELECTOR), addressWord(to), word(amount)));
}

/** `GasPriceOracle.getL1Fee(tx)` calldata: ABI-encoded dynamic `bytes`. */
export function getL1FeeData(tx: Uint8Array): Hex {
  const padded = new Uint8Array(Math.ceil(tx.length / 32) * 32);
  padded.set(tx);
  return hex(concatBytes(unhex(selector("getL1Fee(bytes)")), word(32n), word(BigInt(tx.length)), padded));
}

/** The address that signed `digest`; `v` is 27 or 28 (docs/interfaces.md §4). */
export function recoverAddress(digest: Uint8Array, sig: MpcSignature): string {
  if (sig.v !== 27 && sig.v !== 28) throw new Error(`v must be 27 or 28, got ${sig.v}`);
  const recovered = concatBytes(Uint8Array.of(sig.v - 27), bytes32(sig.r), bytes32(sig.s));
  const pub = secp256k1.recoverPublicKey(recovered, digest, { prehash: false });
  return addressOfPublicKey(pub);
}

export function addressOfPublicKey(pub: Uint8Array): string {
  const uncompressed = secp256k1.Point.fromBytes(pub).toBytes(false);
  return hex(keccak(uncompressed.slice(1)).slice(12));
}

export const addressOfSecret = (sk: Uint8Array) => addressOfPublicKey(secp256k1.getPublicKey(sk));

// ---- RLP and EIP-1559 txs ----

type RlpItem = Uint8Array | RlpItem[];

function rlpLength(len: number, offset: number): Uint8Array {
  if (len <= 55) return Uint8Array.of(offset + len);
  const l = uint(len);
  return concatBytes(Uint8Array.of(offset + 55 + l.length), l);
}

export function rlp(item: RlpItem): Uint8Array {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0] < 0x80) return item;
    return concatBytes(rlpLength(item.length, 0x80), item);
  }
  const body = concatBytes(...item.map(rlp));
  return concatBytes(rlpLength(body.length, 0xc0), body);
}

/** Minimal big-endian bytes of a non-negative integer (0 is empty), as RLP encodes integers. */
function uint(v: bigint | number | string): Uint8Array {
  const n = BigInt(v);
  if (n < 0n) throw new Error(`negative integer: ${v}`);
  if (n === 0n) return new Uint8Array(0);
  const h = n.toString(16);
  return unhex(h.length % 2 ? "0" + h : h);
}

export type Tx1559 = {
  chainId: number | bigint;
  nonce: number | bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gasLimit: number | bigint;
  to: string;
  value: bigint;
  data: Hex;
};

function txFields(t: Tx1559): RlpItem[] {
  return [
    uint(t.chainId),
    uint(t.nonce),
    uint(t.maxPriorityFeePerGas),
    uint(t.maxFeePerGas),
    uint(t.gasLimit),
    unhex(assertAddress("to", t.to)),
    uint(t.value),
    unhex(t.data),
    [],
  ];
}

/** `keccak256(0x02 ‖ rlp([...]))`: the hash a type-2 tx's signature is over. */
export function txDigest(t: Tx1559): Uint8Array {
  return keccak(concatBytes(Uint8Array.of(2), rlp(txFields(t))));
}

/** The signed type-2 tx bytes; `yParity` is 0 or 1. */
export function signedTx(t: Tx1559, yParity: number, r: Hex, s: Hex): Uint8Array {
  return concatBytes(Uint8Array.of(2), rlp([...txFields(t), uint(yParity), uint(BigInt(r)), uint(BigInt(s))]));
}

export function signTx(t: Tx1559, sk: Uint8Array): Uint8Array {
  const sig = secp256k1.sign(txDigest(t), sk, { prehash: false, format: "recovered" });
  return signedTx(t, sig[0], hex(sig.slice(1, 33)), hex(sig.slice(33, 65)));
}

export function payloadTx(p: Eip1559Payload): Tx1559 {
  return {
    chainId: p.chain_id,
    nonce: p.nonce,
    maxPriorityFeePerGas: BigInt(p.max_priority_fee_per_gas),
    maxFeePerGas: BigInt(p.max_fee_per_gas),
    gasLimit: p.gas_limit,
    to: p.to,
    value: BigInt(p.value),
    data: p.data,
  };
}

// ---- Base RPC ----

/** Testnet only: refuses an RPC that is not Base Sepolia. */
export async function assertBaseSepolia(base: Rpc): Promise<void> {
  const id = BigInt(await base("eth_chainId", []));
  if (id !== BigInt(BASE_SEPOLIA_CHAIN_ID)) throw new Error(`Base RPC is chain ${id}, not Base Sepolia (${BASE_SEPOLIA_CHAIN_ID})`);
}

/** Fees for a tx now: twice the base fee plus the node's priority fee. */
export async function currentFees(base: Rpc): Promise<{ baseFee: bigint; maxPriorityFeePerGas: bigint; maxFeePerGas: bigint }> {
  const block = await base("eth_getBlockByNumber", ["latest", false]);
  const baseFee = BigInt(block.baseFeePerGas);
  const maxPriorityFeePerGas = BigInt(await base("eth_maxPriorityFeePerGas", []));
  return { baseFee, maxPriorityFeePerGas, maxFeePerGas: 2n * baseFee + maxPriorityFeePerGas };
}

/** Sends a signed tx; refuses if the node reports a different hash than the bytes have. */
export async function sendRaw(base: Rpc, raw: Uint8Array): Promise<Hex> {
  const want = hex(keccak(raw));
  const got = await base("eth_sendRawTransaction", [hex(raw)]);
  if (typeof got !== "string" || got.toLowerCase() !== want) throw new Error(`node returned tx hash ${got}, expected ${want}`);
  return want;
}

export type Log = { address: string; topics: string[]; data: string };

export async function waitReceipt(base: Rpc, txHash: Hex, opts: { tries?: number; pollMs?: number } = {}): Promise<Log[]> {
  const tries = opts.tries ?? 60;
  for (let i = 0; i < tries; i++) {
    const r = await base("eth_getTransactionReceipt", [txHash]);
    if (r) {
      if (r.status !== "0x1") throw new Error(`tx ${txHash} reverted`);
      return r.logs;
    }
    await sleep(opts.pollMs ?? 2000);
  }
  throw new Error(`no receipt for ${txHash} yet; check it on sepolia.basescan.org before running again`);
}

/** Whether `logs` hold an ERC-20 `Transfer(from, to, amount)` of `token`. */
export function hasTransfer(logs: Log[], token: string, from: string, to: string, amount: bigint): boolean {
  const topic = (a: string) => "0x" + strip0x(a).toLowerCase().padStart(64, "0");
  return logs.some(
    (l) =>
      eqAddr(l.address, token) &&
      l.topics.length === 3 &&
      l.topics[0].toLowerCase() === TRANSFER_TOPIC &&
      l.topics[1].toLowerCase() === topic(from) &&
      l.topics[2].toLowerCase() === topic(to) &&
      BigInt(l.data) === amount,
  );
}

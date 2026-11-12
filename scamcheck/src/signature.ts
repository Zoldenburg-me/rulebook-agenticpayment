import { randomBytes, createHash } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

// NEAR AI Cloud signs each completion inside the model's TEE. This checks that signature and that
// its key is the one NEAR AI's attestation report binds to our nonce. It does not verify the TDX
// quote's Intel signature chain (DCAP), the NVIDIA GPU evidence or the gateway attestation, so the
// trust in the signing key rests on the quote's report_data as NEAR AI serves it.

const VERIFY_TIMEOUT_MS = 10_000;
// TDX quote v4: 48-byte header, then the TD report body with report_data at offset 520 (64 bytes).
const QUOTE_REPORT_DATA = 48 + 520;

export interface SignedText {
  text?: unknown;
  signature?: unknown;
  signing_algo?: unknown;
}

export interface ModelAttestation {
  model_name?: unknown;
  signing_address?: unknown;
  request_nonce?: unknown;
  intel_quote?: unknown;
}

const sha256Hex = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const isHex = (s: unknown, len?: number): s is string =>
  typeof s === "string" && /^[0-9a-f]*$/i.test(s) && s.length % 2 === 0 && (len === undefined || s.length === len);

function addressOf(uncompressed: Uint8Array): string {
  return `0x${bytesToHex(keccak_256(uncompressed.subarray(1)).subarray(12))}`;
}

/** The address an EIP-191 `personal_sign` signature over `text` recovers to, or undefined. */
export function recoverPersonalSign(text: string, signature: string): string | undefined {
  const sig = signature.replace(/^0x/, "");
  if (!isHex(sig, 130)) return undefined;
  const v = parseInt(sig.slice(128), 16);
  const recovery = v >= 27 ? v - 27 : v;
  if (recovery !== 0 && recovery !== 1) return undefined;
  const msg = utf8ToBytes(text);
  const digest = keccak_256(concatBytes(utf8ToBytes(`\x19Ethereum Signed Message:\n${msg.length}`), msg));
  try {
    const pub = secp256k1.recoverPublicKey(hexToBytes(`0${recovery}${sig.slice(0, 128)}`), digest, { prehash: false });
    return addressOf(secp256k1.Point.fromBytes(pub).toBytes(false));
  } catch {
    return undefined;
  }
}

/**
 * The signing address the attestation entry for `model` binds to `nonce`: the TDX quote's
 * report_data must be that address (zero-padded to 32 bytes) followed by the nonce.
 */
export function attestedSigner(report: { model_attestations?: unknown }, model: string, nonce: string): string | undefined {
  const entries = Array.isArray(report?.model_attestations) ? report.model_attestations as ModelAttestation[] : [];
  const e = entries.find(a => a?.model_name === model);
  if (!e || e.request_nonce !== nonce || !isHex(e.intel_quote) || !isHex(nonce, 64)) return undefined;
  const addr = typeof e.signing_address === "string" ? e.signing_address.toLowerCase().replace(/^0x/, "") : "";
  if (!isHex(addr, 40)) return undefined;
  const quote = hexToBytes(e.intel_quote);
  if (quote.length < QUOTE_REPORT_DATA + 64 || quote[0] !== 4 || quote[1] !== 0) return undefined;
  const reportData = bytesToHex(quote.subarray(QUOTE_REPORT_DATA, QUOTE_REPORT_DATA + 64));
  return reportData === `${addr}${"0".repeat(24)}${nonce.toLowerCase()}` ? `0x${addr}` : undefined;
}

/**
 * True only if the signed text is `model:sha256(request):sha256(response)` over the exact bytes
 * sent and received, and its ECDSA signature recovers to `signer`.
 */
export function signatureMatches(sig: SignedText, signer: string, model: string, request: string, response: string): boolean {
  if (sig?.signing_algo !== undefined && sig.signing_algo !== "ecdsa") return false;
  if (typeof sig?.text !== "string" || typeof sig.signature !== "string") return false;
  if (sig.text !== `${model}:${sha256Hex(request)}:${sha256Hex(response)}`) return false;
  return recoverPersonalSign(sig.text, sig.signature) === signer.toLowerCase();
}

export interface VerifyInput {
  baseUrl: string;
  apiKey: string;
  model: string;
  chatId: string;
  request: string;
  response: string;
  fetch: typeof globalThis.fetch;
  timeoutMs?: number;
}

/**
 * Fetches a fresh attestation report and the completion's signature and checks both. Any network,
 * format or verification failure returns false; it never throws.
 */
export async function verifyCompletionSignature(input: VerifyInput): Promise<boolean> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), input.timeoutMs ?? VERIFY_TIMEOUT_MS);
  const get = async (path: string, query: Record<string, string>) => {
    const resp = await input.fetch(`${input.baseUrl}${path}?${new URLSearchParams(query)}`, {
      headers: { Authorization: `Bearer ${input.apiKey}`, Accept: "application/json" },
      signal: controller.signal,
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  };
  try {
    const nonce = randomBytes(32).toString("hex");
    const [report, sig] = await Promise.all([
      get("/attestation/report", { model: input.model, signing_algo: "ecdsa", nonce }),
      get(`/signature/${encodeURIComponent(input.chatId)}`, { model: input.model, signing_algo: "ecdsa" }),
    ]);
    const signer = attestedSigner(report, input.model, nonce);
    return signer !== undefined && signatureMatches(sig, signer, input.model, input.request, input.response);
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

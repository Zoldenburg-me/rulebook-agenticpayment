//! C2 unit tests: owner authorization (passkey and wallet modes), agents, mandates, payees,
//! revoke and the views. Owner assertions are signed with a software P-256 key in exactly the
//! form a WebAuthn authenticator signs (spikes/passkey).

use std::panic::{catch_unwind, AssertUnwindSafe};

use mandate::owner::owner_challenge;
use mandate::shapes::link::LINK_MESSAGE;
use mandate::types::*;
use mandate::Contract;
use near_sdk::base64::engine::general_purpose::URL_SAFE_NO_PAD;
use near_sdk::base64::Engine;
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::mock::MockAction;
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::{
    borsh, env, testing_env, AccountId, NearToken, PromiseOrValue, PromiseResult, PublicKey,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use secp256k1::{Message, Secp256k1, SecretKey};

const CONTRACT: &str = "mandate-demo.testnet";
const NETWORK: &str = "testnet";
const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:5173";
const WALLET: &str = "sme-owner.testnet";
/// Block time of every test (unix s), 300 s before the worked vector's `expires_at`.
const NOW: u64 = 1_793_599_700;
const EXPIRES: u64 = NOW + 300;

/// secp256k1 key pair for link tests (MPC-derived EOA). Fixed seed for reproducibility.
const LINK_SK_BYTES: [u8; 32] = [0x42; 32];

/// Finds the pending link reservation key for `agent` by scanning the contract.
fn link_reservation_key(c: &Contract, agent: &str) -> RequestKey {
    let agent_id: AgentId = agent.into();
    c.list_requests(agent_id, 0, 100)
        .into_iter()
        .find(|r| r.key.caller == Caller::Owner && r.status == RequestStatus::Pending)
        .map(|r| r.key)
        .expect("no pending link reservation")
}

/// Asserts the logs hold exactly one `agent_unlinked` event, for `agent` and `key`.
fn assert_one_agent_unlinked(agent: &str, key: &RequestKey) {
    let unlinked: Vec<near_sdk::serde_json::Value> = get_logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| near_sdk::serde_json::from_str(j).unwrap())
        .filter(|e: &near_sdk::serde_json::Value| e["event"] == "agent_unlinked")
        .collect();
    assert_eq!(unlinked.len(), 1, "one agent_unlinked event");
    assert_eq!(unlinked[0]["data"]["agent"], agent);
    assert_eq!(
        unlinked[0]["data"]["key"],
        near_sdk::serde_json::to_value(key).unwrap()
    );
}

// ---------- environment ----------

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn key(n: u8) -> PublicKey {
    format!("ed25519:{}", near_sdk::bs58::encode([n; 32]).into_string())
        .parse()
        .unwrap()
}

/// The wallet owner attaches 1 yoctoNEAR, as its full-access key must; other callers attach
/// nothing (function-call keys cannot).
fn owner_deposit(predecessor: &str) -> NearToken {
    NearToken::from_yoctonear(if predecessor == WALLET { 1 } else { 0 })
}

/// A call from `predecessor`, signed with `signer_pk`, at `now` (unix s).
fn call_at(predecessor: &str, signer_pk: PublicKey, now: u64, results: Vec<PromiseResult>) {
    let ctx = VMContextBuilder::new()
        .current_account_id(acc(CONTRACT))
        .predecessor_account_id(acc(predecessor))
        .signer_account_id(acc(predecessor))
        .signer_account_pk(signer_pk)
        .attached_deposit(owner_deposit(predecessor))
        .block_timestamp(now * 1_000_000_000)
        .build();
    testing_env!(
        ctx,
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        results
    );
}

/// A call from an ordinary account (a relayer submitting an owner call, or the wallet owner).
fn call_from(predecessor: &str) {
    call_at(predecessor, key(200), NOW, vec![])
}

/// A call signed with an agent key: agent keys live on the contract's own account.
fn agent_call(agent_pk: PublicKey) {
    call_at(CONTRACT, agent_pk, NOW, vec![])
}

/// The callback receipt after a key action that succeeded or failed.
fn callback(ok: bool) {
    let r = if ok {
        PromiseResult::Successful(vec![])
    } else {
        PromiseResult::Failed
    };
    call_at(CONTRACT, key(201), NOW, vec![r]);
}

/// Context for an MPC callback with a specific promise result.
fn mpc_callback(result: PromiseResult) {
    call_at(CONTRACT, key(201), NOW, vec![result]);
}

/// EVM address derived from the fixed link test key.
fn link_evm() -> EvmAddress {
    let secp = Secp256k1::signing_only();
    let sk = SecretKey::from_slice(&LINK_SK_BYTES).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let uncompressed = pk.serialize_uncompressed();
    let hash = near_sdk::env::keccak256_array(&uncompressed[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// EIP-191 digest of the link message.
fn link_digest_bytes() -> [u8; 32] {
    let msg = format!(
        "\x19Ethereum Signed Message:\n{}{}",
        LINK_MESSAGE.len(),
        LINK_MESSAGE
    );
    near_sdk::env::keccak256_array(msg.as_bytes())
}

/// Sign the link digest with a given secret key and return (recovery_id, big_r_x, s_scalar).
fn sign_link(sk_bytes: &[u8; 32]) -> (u8, String, String) {
    let sk = SecretKey::from_slice(sk_bytes).unwrap();
    sign_digest(&link_digest_bytes(), &sk)
}

/// Sign an arbitrary digest with the fixed secp256k1 test key.
fn sign_digest(digest: &[u8; 32], sk: &SecretKey) -> (u8, String, String) {
    let secp = Secp256k1::signing_only();
    let msg = Message::from_slice(digest).unwrap();
    let sig = secp.sign_ecdsa_recoverable(&msg, sk);
    let (rec_id, rs) = sig.serialize_compact();
    let recovery_id = rec_id.to_i32() as u8;
    assert!(recovery_id <= 1);
    let big_r_x = hex::encode(&rs[..32]);
    let prefix = if recovery_id == 1 { "03" } else { "02" };
    let s_scalar = hex::encode(&rs[32..]);
    (recovery_id, format!("{prefix}{big_r_x}"), s_scalar)
}

fn mpc_sweep_ok(digest: [u8; 32]) -> PromiseResult {
    let sk = SecretKey::from_slice(&LINK_SK_BYTES).unwrap();
    let (recovery_id, affine_point, s_scalar) = sign_digest(&digest, &sk);
    let json = format!(
        r#"{{"scheme":"Secp256k1","big_r":{{"affine_point":"{affine_point}"}},"s":{{"scalar":"{s_scalar}"}},"recovery_id":{recovery_id}}}"#,
    );
    PromiseResult::Successful(json.as_bytes().to_vec())
}

/// MPC `sign` response over the link digest with the fixed key.
fn mpc_link_ok() -> PromiseResult {
    let (recovery_id, affine_point, s_scalar) = sign_link(&LINK_SK_BYTES);
    let json = format!(
        r#"{{"scheme":"Secp256k1","big_r":{{"affine_point":"{affine_point}"}},"s":{{"scalar":"{s_scalar}"}},"recovery_id":{recovery_id}}}"#,
    );
    PromiseResult::Successful(json.as_bytes().to_vec())
}

/// A valid MPC signature that recovers to a different address (wrong key).
fn mpc_link_wrong_key() -> PromiseResult {
    let (recovery_id, affine_point, s_scalar) = sign_link(&[0x99; 32]);
    let json = format!(
        r#"{{"scheme":"Secp256k1","big_r":{{"affine_point":"{affine_point}"}},"s":{{"scalar":"{s_scalar}"}},"recovery_id":{recovery_id}}}"#,
    );
    PromiseResult::Successful(json.as_bytes().to_vec())
}

/// Runs `f`, expects it to panic with `"{code}: ..."`, and returns the message.
fn expect_err<R>(code: &str, f: impl FnOnce() -> R) -> String {
    let err = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => panic!("expected {code}, but the call succeeded"),
        Err(e) => e,
    };
    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    // The mock VM wraps the contract's panic as `HostError(GuestPanic { panic_msg: "..." })`.
    let msg = match msg.split_once("panic_msg: \"") {
        Some((_, rest)) => rest.trim_end_matches("\" })").to_string(),
        None => msg,
    };
    assert!(
        msg.starts_with(&format!("{code}: ")),
        "expected {code}, got {msg:?}"
    );
    msg
}

// ---------- software passkey ----------

fn owner_key() -> SigningKey {
    SigningKey::from_slice(&[0x11; 32]).unwrap()
}

fn compressed(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

fn passkey_mode() -> OwnerMode {
    OwnerMode::Passkey {
        public_key: Base64VecU8(compressed(&owner_key())),
        rp_id: RP_ID.into(),
        origin: ORIGIN.into(),
    }
}

/// What the authenticator and the client put into one assertion. Each field can be bent
/// to build a bad assertion.
struct Signing {
    method: &'static str,
    args: Vec<u8>,
    nonce: u64,
    expires_at: u64,
    rp_id: &'static str,
    flags: u8,
    kind: &'static str,
    origin: &'static str,
    key: SigningKey,
}

impl Signing {
    fn new(method: &'static str, args: Vec<u8>, nonce: u64) -> Self {
        Signing {
            method,
            args,
            nonce,
            expires_at: EXPIRES,
            rp_id: RP_ID,
            flags: 0x05, // UP | UV
            kind: "webauthn.get",
            origin: ORIGIN,
            key: owner_key(),
        }
    }

    fn challenge(&self) -> String {
        let digest = owner_challenge(
            CONTRACT,
            NETWORK,
            self.method,
            &self.args,
            self.nonce,
            self.expires_at,
        );
        URL_SAFE_NO_PAD.encode(digest)
    }

    fn sign_with_challenge(&self, challenge: &str) -> OwnerAssertion {
        let mut auth_data = env::sha256_array(self.rp_id.as_bytes()).to_vec();
        auth_data.push(self.flags);
        auth_data.extend_from_slice(&0u32.to_be_bytes()); // signCount 0, as synced passkeys
        let cdj = format!(
            r#"{{"type":"{}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            self.kind, challenge, self.origin
        );
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&env::sha256_array(cdj.as_bytes()));
        let sig: Signature = self.key.sign(&signed); // ES256: SHA-256 inside
        OwnerAssertion {
            authenticator_data: Base64VecU8(auth_data),
            client_data_json: cdj,
            signature: Base64VecU8(sig.to_bytes().to_vec()),
            owner_nonce: self.nonce,
            expires_at: self.expires_at,
        }
    }

    fn sign(&self) -> OwnerAssertion {
        self.sign_with_challenge(&self.challenge())
    }
}

/// The (r, n − s) twin of a raw signature: the other S form.
fn flip_s(raw: &[u8]) -> Vec<u8> {
    let sig = Signature::from_slice(raw).unwrap();
    Signature::from_scalars(sig.r(), -*sig.s())
        .unwrap()
        .to_bytes()
        .to_vec()
}

fn relayer_args(account: &str) -> Vec<u8> {
    borsh::to_vec(&(Some(acc(account)),)).unwrap()
}

fn agent_args(agent: &str) -> Vec<u8> {
    borsh::to_vec(&(agent.to_string(),)).unwrap()
}

// ---------- fixtures ----------

fn sweep_config() -> SweepConfig {
    SweepConfig {
        safe_address: "0x5AFE000000000000000000000000000000000001".into(),
        usdc_address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e".into(),
        eure_address: "0x29f37f6adca168b79b8d9567eab9be3fbf21db85".into(),
        chain_id: 84532,
        usdc_eip712_name: "USDC".into(),
        usdc_eip712_version: "2".into(),
    }
}

/// The agent EOA the owner derives off chain; mixed case to check it is stored lowercase.
fn evm() -> EvmAddress {
    "0xAbCdEf0123456789aBcDeF0123456789ABCDEF01".into()
}

fn rail(max: u128, budget: u128) -> RailMandate {
    RailMandate {
        amount_range: AmountRange {
            min: U128(1),
            max: U128(max),
        },
        budget: U128(budget),
        period_secs: 604_800,
    }
}

fn mandate() -> Mandate {
    Mandate {
        x402: rail(1_000_000, 20_000_000),
        sepa: rail(50 * 10u128.pow(18), 200 * 10u128.pow(18)),
        usdc_address: "0x036CBD53842c5426634e7929541eC2318f3dCF7e".into(),
        eure_address: "0x29f37f6adca168b79b8d9567eab9be3fbf21db85".into(),
        chain_id: 84532,
        float_cap: FloatCap {
            usdc: U128(25_000_000),
            eure: U128(250 * 10u128.pow(18)),
        },
        max_validity_secs: 300,
        paypal: None,
        paypal_refund: None,
        usdc_eip712_name: "USDC".into(),
        usdc_eip712_version: "2".into(),
    }
}

fn new_passkey() -> Contract {
    call_from("deployer.testnet");
    Contract::new(
        passkey_mode(),
        NETWORK.into(),
        acc("v1.signer-prod.testnet"),
    )
}

fn new_wallet() -> Contract {
    call_from("deployer.testnet");
    Contract::new(
        OwnerMode::Wallet {
            account: acc(WALLET),
        },
        NETWORK.into(),
        acc("v1.signer-prod.testnet"),
    )
}

/// Wallet owner adds `agent` with `pk`, and the `AddKey` succeeds.
fn add(c: &mut Contract, agent: &str, pk: PublicKey) {
    call_from(WALLET);
    let _ = c.add_agent(agent.into(), pk.clone(), sweep_config(), evm(), None);
    callback(true);
    assert!(c.on_agent_key_added(agent.into(), pk));
}

/// Wallet contract with agents A (key 1) and B (key 2), each with a mandate and a payee.
fn two_agents() -> Contract {
    let mut c = new_wallet();
    add(&mut c, "agent-a", key(1));
    add(&mut c, "agent-b", key(2));
    call_from(WALLET);
    for a in ["agent-a", "agent-b"] {
        c.set_mandate(a.into(), mandate(), None);
        c.add_payee(
            a.into(),
            Payee::Sepa {
                iban: "DE89370400440532013000".into(),
            },
            None,
        );
    }
    c
}

fn delete_key_receipt() -> Option<String> {
    get_created_receipts()
        .into_iter()
        .flat_map(|r| r.actions)
        .find_map(|a| match a {
            MockAction::DeleteKey { public_key, .. } => Some(public_key.to_string()),
            _ => None,
        })
}

// ---------- challenge encoding ----------

#[test]
fn challenge_matches_the_worked_vector_in_interfaces_md() {
    call_from("anyone.testnet");
    let digest = owner_challenge(
        CONTRACT,
        NETWORK,
        "set_relayer",
        &relayer_args("relayer-demo.testnet"),
        1,
        1_793_600_000,
    );
    assert_eq!(
        hex::encode(digest),
        "ec27a25ee1455067baa5daecd431d5c72f6b40842bf3c0df9a8c284b17bd72c5"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(digest),
        "7CeiXuFFUGe6pdrs1DHVxy9rQIQr88DfmowoSxe9csU"
    );
}

// ---------- passkey owner ----------

#[test]
fn valid_assertion_is_accepted_from_any_submitter_and_consumes_the_nonce() {
    let mut c = new_passkey();
    call_from("anyone-pays-gas.testnet");
    let a = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1).sign();
    c.set_relayer(Some(acc("relayer-demo.testnet")), Some(a));
    let cfg = c.get_config();
    assert_eq!(cfg.relayer, Some(acc("relayer-demo.testnet")));
    assert_eq!(cfg.owner_nonce, 1);
}

#[test]
fn high_s_signature_is_accepted() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let mut a = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1).sign();
    a.signature = Base64VecU8(flip_s(&a.signature.0));
    c.set_relayer(Some(acc("relayer-demo.testnet")), Some(a));
    assert_eq!(c.get_config().owner_nonce, 1);
}

#[test]
fn replayed_assertion_is_rejected() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let a = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1).sign();
    c.set_relayer(Some(acc("relayer-demo.testnet")), Some(a.clone()));
    expect_err("ERR_ASSERTION_STALE_NONCE", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), Some(a))
    });
}

#[test]
fn stale_owner_nonce_fails_loudly() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    c.set_relayer(
        Some(acc("relayer-demo.testnet")),
        Some(Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 5).sign()),
    );
    // Signed earlier with nonce 3, submitted after nonce 5 was used: the owner must re-sign.
    let old = Signing::new("set_relayer", relayer_args("other-relayer.testnet"), 3).sign();
    let msg = expect_err("ERR_ASSERTION_STALE_NONCE", || {
        c.set_relayer(Some(acc("other-relayer.testnet")), Some(old))
    });
    assert!(msg.contains("3") && msg.contains("5"), "{msg}");
    assert_eq!(c.get_config().relayer, Some(acc("relayer-demo.testnet")));
}

#[test]
fn owner_nonce_may_advance_by_at_most_max_owner_nonce_step() {
    // SEC-4: a jump to u64::MAX would lock the owner out for good.
    let mut c = new_passkey();
    call_from("anyone.testnet");
    for nonce in [MAX_OWNER_NONCE_STEP + 1, u64::MAX] {
        let a = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), nonce).sign();
        expect_err("ERR_ASSERTION_STALE_NONCE", || {
            c.set_relayer(Some(acc("relayer-demo.testnet")), Some(a))
        });
    }
    assert_eq!(c.get_config().owner_nonce, 0);
    let a = Signing::new(
        "set_relayer",
        relayer_args("relayer-demo.testnet"),
        MAX_OWNER_NONCE_STEP,
    )
    .sign();
    c.set_relayer(Some(acc("relayer-demo.testnet")), Some(a));
    assert_eq!(c.get_config().owner_nonce, MAX_OWNER_NONCE_STEP);
    assert_eq!(MAX_OWNER_NONCE_STEP, 1000);
}

#[test]
fn failed_assertion_does_not_consume_the_nonce() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let mut bad = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1);
    bad.rp_id = "evil.example";
    expect_err("ERR_ASSERTION_BAD_RP_ID_HASH", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), Some(bad.sign()))
    });
    assert_eq!(c.get_config().owner_nonce, 0);
    let good = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1).sign();
    c.set_relayer(Some(acc("relayer-demo.testnet")), Some(good));
    assert_eq!(c.get_config().owner_nonce, 1);
}

#[test]
fn expired_assertion_is_rejected() {
    let mut c = new_passkey();
    let a = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1).sign();
    // Submitted at expires_at: already passed.
    call_at("anyone.testnet", key(200), EXPIRES, vec![]);
    expect_err("ERR_ASSERTION_EXPIRED", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), Some(a))
    });
}

#[test]
fn assertion_with_too_long_ttl_is_rejected() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let mut s = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1);
    s.expires_at = NOW + MAX_ASSERTION_TTL_SECS + 1;
    expect_err("ERR_ASSERTION_TTL_TOO_LONG", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), Some(s.sign()))
    });
}

#[test]
fn wrong_rp_id_hash_is_rejected() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let mut s = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1);
    s.rp_id = "localhost.evil.example";
    expect_err("ERR_ASSERTION_BAD_RP_ID_HASH", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), Some(s.sign()))
    });
}

#[test]
fn assertion_for_different_args_is_rejected() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let a = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1).sign();
    expect_err("ERR_ASSERTION_BAD_CHALLENGE", || {
        c.set_relayer(Some(acc("attacker.testnet")), Some(a))
    });
}

#[test]
fn assertion_for_a_different_method_is_rejected() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    // An assertion for `revoke("agent-a")` cannot authorize another method.
    let a = Signing::new("revoke", agent_args("agent-a"), 1).sign();
    expect_err("ERR_ASSERTION_BAD_CHALLENGE", || {
        c.add_payee(
            "agent-a".into(),
            Payee::Sepa {
                iban: "DE89370400440532013000".into(),
            },
            Some(a),
        )
    });
}

#[test]
fn assertion_without_user_presence_is_rejected() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let mut s = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1);
    s.flags = 0x04; // UV only
    expect_err("ERR_ASSERTION_NO_USER_PRESENCE", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), Some(s.sign()))
    });
}

#[test]
fn wrong_type_origin_or_key_is_rejected() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let relayer = || Some(acc("relayer-demo.testnet"));
    let base = || Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1);

    let mut s = base();
    s.kind = "webauthn.create";
    expect_err("ERR_ASSERTION_BAD_TYPE", || {
        c.set_relayer(relayer(), Some(s.sign()))
    });

    let mut s = base();
    s.origin = "http://localhost:5174"; // the port counts
    expect_err("ERR_ASSERTION_BAD_ORIGIN", || {
        c.set_relayer(relayer(), Some(s.sign()))
    });

    let mut s = base();
    s.key = SigningKey::from_slice(&[0x22; 32]).unwrap();
    expect_err("ERR_ASSERTION_BAD_SIGNATURE", || {
        c.set_relayer(relayer(), Some(s.sign()))
    });

    // A valid signature over different authenticator data.
    let mut a = base().sign();
    a.authenticator_data.0[33] ^= 1; // signCount byte: covered by the signature only
    expect_err("ERR_ASSERTION_BAD_SIGNATURE", || {
        c.set_relayer(relayer(), Some(a))
    });

    let mut a = base().sign();
    a.signature.0.pop();
    expect_err("ERR_ASSERTION_MALFORMED", || {
        c.set_relayer(relayer(), Some(a))
    });

    let mut a = base().sign();
    a.authenticator_data.0.truncate(36);
    expect_err("ERR_ASSERTION_MALFORMED", || {
        c.set_relayer(relayer(), Some(a))
    });
}

#[test]
fn challenge_must_be_strict_unpadded_base64url() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    // A nonce whose challenge has a `-` or `_`, so the standard alphabet differs.
    let s = (1..100)
        .map(|n| Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), n))
        .find(|s| s.challenge().contains(['-', '_']))
        .unwrap();
    let canonical = s.challenge();
    // Padded, and standard-alphabet forms of the same bytes, each properly signed.
    let padded = format!("{canonical}=");
    let standard = near_sdk::base64::engine::general_purpose::STANDARD_NO_PAD
        .encode(URL_SAFE_NO_PAD.decode(&canonical).unwrap());
    for bad in [padded, standard] {
        let a = s.sign_with_challenge(&bad);
        expect_err("ERR_ASSERTION_BAD_CHALLENGE", || {
            c.set_relayer(Some(acc("relayer-demo.testnet")), Some(a))
        });
    }
}

#[test]
fn passkey_mode_requires_an_assertion() {
    let mut c = new_passkey();
    call_from(WALLET);
    expect_err("ERR_ASSERTION_REQUIRED", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), None)
    });
}

#[test]
fn passkey_add_agent_and_revoke_end_to_end() {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let args = borsh::to_vec(&("agent-a".to_string(), key(1), sweep_config(), evm())).unwrap();
    let a = Signing::new("add_agent", args, 1).sign();
    let _ = c.add_agent("agent-a".into(), key(1), sweep_config(), evm(), Some(a));
    assert_eq!(c.agent_of_key(key(1)), Some("agent-a".to_string()));

    call_from("anyone.testnet");
    let a = Signing::new("revoke", agent_args("agent-a"), 2).sign();
    let _ = c.revoke("agent-a".into(), Some(a));
    assert_eq!(c.agent_of_key(key(1)), None);
    assert!(c.get_agent("agent-a".into()).unwrap().revoked);
    assert_eq!(c.get_config().owner_nonce, 2);
}

// ---------- wallet owner ----------

#[test]
fn wallet_owner_calls_from_the_owner_account() {
    let mut c = new_wallet();
    call_from(WALLET);
    c.set_relayer(Some(acc("relayer-demo.testnet")), None);
    assert_eq!(c.get_config().relayer, Some(acc("relayer-demo.testnet")));
    assert_eq!(c.get_config().owner_nonce, 0);
}

#[test]
fn wallet_mode_rejects_other_accounts() {
    let mut c = new_wallet();
    call_from("someone-else.testnet");
    expect_err("ERR_NOT_OWNER", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), None)
    });
    expect_err("ERR_NOT_OWNER", || {
        c.add_agent("agent-a".into(), key(1), sweep_config(), evm(), None)
    });
}

#[test]
fn wallet_mode_rejects_a_call_carrying_an_assertion() {
    let mut c = new_wallet();
    call_from(WALLET);
    let a = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1).sign();
    expect_err("ERR_ASSERTION_FORBIDDEN", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), Some(a))
    });
}

#[test]
fn new_rejects_this_contract_as_wallet_owner_and_bad_passkeys() {
    call_from("deployer.testnet");
    let mpc = || acc("v1.signer-prod.testnet");
    expect_err("ERR_NOT_OWNER", || {
        Contract::new(
            OwnerMode::Wallet {
                account: acc(CONTRACT),
            },
            NETWORK.into(),
            mpc(),
        )
    });
    let uncompressed = owner_key()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    expect_err("ERR_NOT_OWNER", || {
        Contract::new(
            OwnerMode::Passkey {
                public_key: Base64VecU8(uncompressed),
                rp_id: RP_ID.into(),
                origin: ORIGIN.into(),
            },
            NETWORK.into(),
            mpc(),
        )
    });
}

#[test]
fn set_relayer_by_non_owner_is_rejected() {
    let mut c = new_wallet();
    call_from("relayer-demo.testnet");
    expect_err("ERR_NOT_OWNER", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), None)
    });

    let mut c = new_passkey();
    call_from("relayer-demo.testnet");
    let mut s = Signing::new("set_relayer", relayer_args("relayer-demo.testnet"), 1);
    s.key = SigningKey::from_slice(&[0x33; 32]).unwrap();
    expect_err("ERR_ASSERTION_BAD_SIGNATURE", || {
        c.set_relayer(Some(acc("relayer-demo.testnet")), Some(s.sign()))
    });
    assert_eq!(c.get_config().relayer, None);
}

#[test]
fn set_relayer_rejects_this_contract_and_none_removes_it() {
    let mut c = new_wallet();
    call_from(WALLET);
    expect_err("ERR_SWEEP_CALLER_NOT_ALLOWED", || {
        c.set_relayer(Some(acc(CONTRACT)), None)
    });
    c.set_relayer(Some(acc("relayer-demo.testnet")), None);
    c.set_relayer(None, None);
    assert_eq!(c.get_config().relayer, None);
}

// ---------- agents calling owner methods ----------

#[test]
fn agent_key_calling_owner_methods_is_rejected() {
    // Passkey mode: the agent has no owner assertion.
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let args = borsh::to_vec(&("agent-a".to_string(), key(1), sweep_config(), evm())).unwrap();
    let _ = c.add_agent(
        "agent-a".into(),
        key(1),
        sweep_config(),
        evm(),
        Some(Signing::new("add_agent", args, 1).sign()),
    );
    agent_call(key(1));
    expect_err("ERR_ASSERTION_REQUIRED", || {
        c.set_mandate("agent-a".into(), mandate(), None)
    });
    expect_err("ERR_ASSERTION_REQUIRED", || {
        c.revoke("agent-a".into(), None)
    });
    expect_err("ERR_ASSERTION_REQUIRED", || {
        c.set_relayer(Some(acc(CONTRACT)), None)
    });

    // Wallet mode: the agent's predecessor is this contract, never the owner account.
    let mut c = two_agents();
    agent_call(key(1));
    expect_err("ERR_NOT_OWNER", || {
        c.set_mandate("agent-a".into(), mandate(), None)
    });
    expect_err("ERR_NOT_OWNER", || {
        c.add_payee(
            "agent-a".into(),
            Payee::Sepa {
                iban: "GB33BUKB20201555555555".into(),
            },
            None,
        )
    });
    expect_err("ERR_NOT_OWNER", || c.revoke("agent-b".into(), None));
    expect_err("ERR_NOT_OWNER", || {
        c.add_agent("agent-c".into(), key(3), sweep_config(), evm(), None)
    });
}

// ---------- add_agent ----------

#[test]
fn add_agent_adds_a_three_method_key_and_stores_the_sweep_config() {
    let mut c = new_wallet();
    call_from(WALLET);
    let _ = c.add_agent("agent-a".into(), key(1), sweep_config(), evm(), None);
    let add_key = get_created_receipts()
        .into_iter()
        .flat_map(|r| r.actions)
        .find_map(|a| match a {
            MockAction::AddKeyWithFunctionCall {
                public_key,
                allowance,
                receiver_id,
                method_names,
                ..
            } => Some((public_key.to_string(), allowance, receiver_id, method_names)),
            _ => None,
        })
        .expect("AddKey receipt");
    assert_eq!(add_key.0, key(1).to_string());
    assert_eq!(add_key.1, Some(NearToken::from_near(1)));
    assert_eq!(add_key.2, acc(CONTRACT));
    assert_eq!(add_key.3, AGENT_METHOD_NAMES.map(String::from).to_vec());

    let rec = c.get_agent("agent-a".into()).unwrap();
    assert_eq!(rec.public_key, Some(key(1)));
    assert_eq!(
        rec.sweep_config.safe_address,
        "0x5afe000000000000000000000000000000000001"
    );
    assert_eq!(
        rec.evm_address.as_deref(),
        Some("0xabcdef0123456789abcdef0123456789abcdef01")
    );
    assert!(!rec.revoked);
    assert_eq!(c.agent_of_key(key(1)), Some("agent-a".to_string()));
    assert!(get_logs()
        .iter()
        .any(|l| l.contains("\"event\":\"agent_added\"")));
}

#[test]
fn add_agent_with_existing_agent_or_key_is_rejected() {
    let mut c = new_wallet();
    // The map entry is written before AddKey, so a second call is refused before any callback.
    call_from(WALLET);
    let _ = c.add_agent("agent-a".into(), key(1), sweep_config(), evm(), None);
    expect_err("ERR_AGENT_EXISTS", || {
        c.add_agent("agent-a".into(), key(2), sweep_config(), evm(), None)
    });
    expect_err("ERR_KEY_EXISTS", || {
        c.add_agent("agent-b".into(), key(1), sweep_config(), evm(), None)
    });
}

#[test]
fn revoked_agent_id_is_never_reused() {
    let mut c = two_agents();
    call_from(WALLET);
    let _ = c.revoke("agent-a".into(), None);
    expect_err("ERR_AGENT_EXISTS", || {
        c.add_agent("agent-a".into(), key(9), sweep_config(), evm(), None)
    });
}

#[test]
fn add_agent_validates_id_and_addresses() {
    let mut c = new_wallet();
    call_from(WALLET);
    expect_err("ERR_INVALID_AGENT_ID", || {
        c.add_agent("".into(), key(1), sweep_config(), evm(), None)
    });
    expect_err("ERR_INVALID_AGENT_ID", || {
        c.add_agent("a/b".into(), key(1), sweep_config(), evm(), None)
    });
    let mut sc = sweep_config();
    sc.safe_address = "0x5afe".into();
    expect_err("ERR_INVALID_ADDRESS", || {
        c.add_agent("agent-a".into(), key(1), sc, evm(), None)
    });
}

#[test]
fn add_agent_accepts_base_sepolia_only() {
    let mut c = new_wallet();
    call_from(WALLET);
    for chain_id in [8453, 1, 11155111] {
        let mut sc = sweep_config();
        sc.chain_id = chain_id;
        expect_err("ERR_WRONG_NETWORK", || {
            c.add_agent("agent-a".into(), key(1), sc, evm(), None)
        });
    }
    assert!(c.get_agent("agent-a".into()).is_none());
    let _ = c.add_agent("agent-a".into(), key(1), sweep_config(), evm(), None);
    assert_eq!(
        c.get_agent("agent-a".into()).unwrap().sweep_config.chain_id,
        BASE_SEPOLIA_CHAIN_ID
    );
}

#[test]
fn add_agent_validates_the_evm_address() {
    let mut c = new_wallet();
    call_from(WALLET);
    for bad in [
        "",
        "abcdef0123456789abcdef0123456789abcdef01",
        "0xabcdef0123456789abcdef0123456789abcdef0",
        "0xabcdef0123456789abcdef0123456789abcdef012",
        "0xabcdef0123456789abcdef0123456789abcdefg1",
        "0Xabcdef0123456789abcdef0123456789abcdef01",
    ] {
        let msg = expect_err("ERR_INVALID_ADDRESS", || {
            c.add_agent("agent-a".into(), key(1), sweep_config(), bad.into(), None)
        });
        assert!(msg.contains("evm_address"), "{msg}");
    }
    assert!(c.get_agent("agent-a".into()).is_none());
    assert_eq!(c.agent_of_key(key(1)), None);
}

#[test]
fn failed_add_key_clears_the_entry_and_retires_the_id() {
    let mut c = new_wallet();
    call_from(WALLET);
    let _ = c.add_agent("agent-a".into(), key(1), sweep_config(), evm(), None);
    callback(false);
    assert!(!c.on_agent_key_added("agent-a".into(), key(1)));
    assert_eq!(c.agent_of_key(key(1)), None);
    let rec = c.get_agent("agent-a".into()).unwrap();
    assert!(rec.revoked && rec.public_key.is_none());
    assert!(get_logs()
        .iter()
        .any(|l| l.contains("\"event\":\"agent_add_failed\"")));
    // The key is free again, under a new id.
    call_from(WALLET);
    let _ = c.add_agent("agent-a2".into(), key(1), sweep_config(), evm(), None);
    assert_eq!(c.agent_of_key(key(1)), Some("agent-a2".to_string()));
}

// ---------- mandate and payees ----------

#[test]
fn set_mandate_stores_lowercase_and_checks_the_sweep_config() {
    let mut c = two_agents();
    let m = c.get_mandate("agent-a".into()).unwrap();
    assert_eq!(m.usdc_address, "0x036cbd53842c5426634e7929541ec2318f3dcf7e");

    call_from(WALLET);
    // Testnet only: Base mainnet (8453) is refused before the sweep-config comparison.
    let mut m = mandate();
    m.chain_id = 8453;
    expect_err("ERR_WRONG_NETWORK", || {
        c.set_mandate("agent-a".into(), m, None)
    });
    let mut m = mandate();
    m.usdc_address = "0x0000000000000000000000000000000000000001".into();
    expect_err("ERR_INVALID_MANDATE", || {
        c.set_mandate("agent-a".into(), m, None)
    });
    for v in [MIN_VALIDITY_SECS - 1, MAX_VALIDITY_CAP_SECS + 1] {
        let mut m = mandate();
        m.max_validity_secs = v;
        expect_err("ERR_INVALID_MANDATE", || {
            c.set_mandate("agent-a".into(), m, None)
        });
    }
    let mut m = mandate();
    m.x402.amount_range.min = U128(2_000_000);
    expect_err("ERR_INVALID_MANDATE", || {
        c.set_mandate("agent-a".into(), m, None)
    });
    expect_err("ERR_UNKNOWN_AGENT", || {
        c.set_mandate("nobody".into(), mandate(), None)
    });
}

#[test]
fn eip712_domain_is_bounded_and_validated_at_creation() {
    // PP1: name 1-32, version 1-8 bytes of printable ASCII, else ERR_WRONG_ASSET.
    let long_name = "N".repeat(33);
    let bad_names = ["", long_name.as_str(), "USD\u{0}C", "USDC\n", "PayPal USDÉ"];
    let bad_versions = ["", "123456789", "1\t", "v\u{7f}"];

    let mut c = new_wallet();
    call_from(WALLET);
    for name in bad_names {
        let mut sc = sweep_config();
        sc.usdc_eip712_name = name.into();
        let msg = expect_err("ERR_WRONG_ASSET", || {
            c.add_agent("agent-x".into(), key(9), sc, evm(), None)
        });
        assert!(msg.contains("sweep_config.usdc_eip712_name"), "{msg}");
    }
    for version in bad_versions {
        let mut sc = sweep_config();
        sc.usdc_eip712_version = version.into();
        let msg = expect_err("ERR_WRONG_ASSET", || {
            c.add_agent("agent-x".into(), key(9), sc, evm(), None)
        });
        assert!(msg.contains("sweep_config.usdc_eip712_version"), "{msg}");
    }
    assert!(c.get_agent("agent-x".into()).is_none());

    let mut c = two_agents();
    call_from(WALLET);
    for name in bad_names {
        let mut m = mandate();
        m.usdc_eip712_name = name.into();
        let msg = expect_err("ERR_WRONG_ASSET", || {
            c.set_mandate("agent-a".into(), m, None)
        });
        assert!(msg.contains("mandate.usdc_eip712_name"), "{msg}");
    }
    for version in bad_versions {
        let mut m = mandate();
        m.usdc_eip712_version = version.into();
        let msg = expect_err("ERR_WRONG_ASSET", || {
            c.set_mandate("agent-a".into(), m, None)
        });
        assert!(msg.contains("mandate.usdc_eip712_version"), "{msg}");
    }
    // Well-formed but different from the sweep config: refused, so the two never disagree.
    let mut m = mandate();
    m.usdc_eip712_name = "PayPal USD".into();
    m.usdc_eip712_version = "1".into();
    expect_err("ERR_INVALID_MANDATE", || {
        c.set_mandate("agent-a".into(), m, None)
    });
    let mut m = mandate();
    m.usdc_eip712_version = "1".into();
    expect_err("ERR_INVALID_MANDATE", || {
        c.set_mandate("agent-a".into(), m, None)
    });
    assert_eq!(c.get_mandate("agent-a".into()).unwrap(), {
        let mut m = mandate();
        m.usdc_address = m.usdc_address.to_ascii_lowercase();
        m
    });
}

#[test]
fn eip712_domain_at_the_bounds_is_stored() {
    let name = "P".repeat(32);
    let version = "~".repeat(8);
    let mut c = new_wallet();
    call_from(WALLET);
    let mut sc = sweep_config();
    sc.usdc_eip712_name = name.clone();
    sc.usdc_eip712_version = version.clone();
    let _ = c.add_agent("agent-p".into(), key(7), sc, evm(), None);
    let rec = c.get_agent("agent-p".into()).unwrap();
    assert_eq!(
        (
            rec.sweep_config.usdc_eip712_name.as_str(),
            rec.sweep_config.usdc_eip712_version.as_str()
        ),
        (name.as_str(), version.as_str())
    );
    call_from(WALLET);
    let mut m = mandate();
    m.usdc_eip712_name = name.clone();
    m.usdc_eip712_version = version.clone();
    c.set_mandate("agent-p".into(), m, None);
    let m = c.get_mandate("agent-p".into()).unwrap();
    assert_eq!((m.usdc_eip712_name, m.usdc_eip712_version), (name, version));
}

#[test]
fn mandate_json_without_eip712_domain_defaults_to_usdc_2() {
    // Mandates and sweep configs written before PP1 omit the fields.
    let m: Mandate = near_sdk::serde_json::from_value(near_sdk::serde_json::json!({
        "x402": { "amount_range": { "min": "1", "max": "1000000" }, "budget": "20000000", "period_secs": 604800 },
        "sepa": { "amount_range": { "min": "1", "max": "50000000000000000000" }, "budget": "200000000000000000000", "period_secs": 604800 },
        "usdc_address": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
        "eure_address": "0x29f37f6adca168b79b8d9567eab9be3fbf21db85",
        "chain_id": 84532,
        "float_cap": { "usdc": "25000000", "eure": "250000000000000000000" },
        "max_validity_secs": 300
    }))
    .unwrap();
    assert_eq!(
        (m.usdc_eip712_name.as_str(), m.usdc_eip712_version.as_str()),
        ("USDC", "2")
    );
    let sc: SweepConfig = near_sdk::serde_json::from_value(near_sdk::serde_json::json!({
        "safe_address": "0x5afe000000000000000000000000000000000001",
        "usdc_address": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
        "eure_address": "0x29f37f6adca168b79b8d9567eab9be3fbf21db85",
        "chain_id": 84532
    }))
    .unwrap();
    assert_eq!(
        (
            sc.usdc_eip712_name.as_str(),
            sc.usdc_eip712_version.as_str()
        ),
        ("USDC", "2")
    );
}

#[test]
fn set_mandate_does_not_restart_the_budget_window() {
    let mut c = two_agents();
    let first = c.get_budget("agent-a".into(), Rail::X402).unwrap();
    assert_eq!(first.period_start_ms, NOW * 1000);
    assert_eq!(first.reserved, U128(0));

    // A day later the owner changes the mandate, including the period.
    call_at(WALLET, key(200), NOW + 86_400, vec![]);
    let mut m = mandate();
    m.x402.period_secs = 3600;
    m.x402.budget = U128(5);
    c.set_mandate("agent-a".into(), m, None);
    let b = c.get_budget("agent-a".into(), Rail::X402).unwrap();
    assert_eq!(
        (b.period_start_ms, b.period_secs, b.budget),
        (NOW * 1000, 604_800, U128(5))
    );

    // After the first week ends, windows are one hour long, back to back.
    call_at(WALLET, key(200), NOW + 604_800 + 2 * 3600 + 10, vec![]);
    let b = c.get_budget("agent-a".into(), Rail::X402).unwrap();
    assert_eq!(
        (b.period_start_ms, b.period_secs),
        ((NOW + 604_800 + 2 * 3600) * 1000, 3600)
    );
}

#[test]
fn changed_period_does_not_rewrite_elapsed_windows() {
    let mut c = new_wallet();
    add(&mut c, "agent-a", key(1));
    call_from(WALLET);
    let mut m = mandate();
    m.x402.period_secs = 3600;
    c.set_mandate("agent-a".into(), m.clone(), None);

    // No requests. At +1.5 h the period becomes a day: the 1-2 h window keeps its end.
    call_at(WALLET, key(200), NOW + 5400, vec![]);
    m.x402.period_secs = 86_400;
    c.set_mandate("agent-a".into(), m, None);
    let b = c.get_budget("agent-a".into(), Rail::X402).unwrap();
    assert_eq!(
        (b.period_start_ms, b.period_secs),
        ((NOW + 3600) * 1000, 3600)
    );

    // From the next boundary (+2 h), windows are a day long.
    call_at(WALLET, key(200), NOW + 7201, vec![]);
    let b = c.get_budget("agent-a".into(), Rail::X402).unwrap();
    assert_eq!(
        (b.period_start_ms, b.period_secs),
        ((NOW + 7200) * 1000, 86_400)
    );
}

#[test]
fn period_change_exactly_at_a_boundary_applies_at_once() {
    let mut c = new_wallet();
    add(&mut c, "agent-a", key(1));
    call_from(WALLET);
    let mut m = mandate();
    m.x402.period_secs = 3600;
    c.set_mandate("agent-a".into(), m.clone(), None);

    // At exactly +1 h a new window begins; it takes the new one-day period.
    call_at(WALLET, key(200), NOW + 3600, vec![]);
    m.x402.period_secs = 86_400;
    c.set_mandate("agent-a".into(), m, None);
    let b = c.get_budget("agent-a".into(), Rail::X402).unwrap();
    assert_eq!(
        (b.period_start_ms, b.period_secs),
        ((NOW + 3600) * 1000, 86_400)
    );
    call_at(WALLET, key(200), NOW + 7201, vec![]);
    let b = c.get_budget("agent-a".into(), Rail::X402).unwrap();
    assert_eq!(
        (b.period_start_ms, b.period_secs),
        ((NOW + 3600) * 1000, 86_400)
    );
}

#[test]
fn payees_are_added_once_and_removed_loudly() {
    let mut c = two_agents();
    call_from(WALLET);
    let pay_to = Payee::X402 {
        pay_to: "0xEEA5E3BCC1E058AEF9586A1C5C4CADC9CFDBC74F".into(),
    };
    c.add_payee("agent-a".into(), pay_to.clone(), None);
    c.add_payee("agent-a".into(), pay_to.clone(), None);
    let lower = Payee::X402 {
        pay_to: "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f".into(),
    };
    assert_eq!(
        c.get_payees("agent-a".into()),
        vec![
            Payee::Sepa {
                iban: "DE89370400440532013000".into()
            },
            lower.clone()
        ]
    );
    c.remove_payee("agent-a".into(), lower.clone(), None);
    expect_err("ERR_PAYEE_NOT_ALLOWED", || {
        c.remove_payee("agent-a".into(), lower, None)
    });
    expect_err("ERR_IBAN_NOT_ALLOWED", || {
        c.remove_payee(
            "agent-a".into(),
            Payee::Sepa {
                iban: "GB33BUKB20201555555555".into(),
            },
            None,
        )
    });
    expect_err("ERR_INVALID_IBAN", || {
        c.add_payee(
            "agent-a".into(),
            Payee::Sepa {
                iban: "de89 3704 0044 0532 0130 00".into(),
            },
            None,
        )
    });
    expect_err("ERR_INVALID_ADDRESS", || {
        c.add_payee(
            "agent-a".into(),
            Payee::X402 {
                pay_to: "eea5e3bc".into(),
            },
            None,
        )
    });
    // Agent B's list is its own.
    assert_eq!(c.get_payees("agent-b".into()).len(), 1);
}

// ---------- revoke ----------

#[test]
fn revoke_by_owner_clears_state_and_deletes_the_key() {
    let mut c = two_agents();
    call_from(WALLET);
    let r = c.revoke("agent-a".into(), None);
    assert!(matches!(r, PromiseOrValue::Promise(_)));
    drop(r); // near-sdk schedules a promise when it is dropped
    assert_eq!(delete_key_receipt(), Some(key(1).to_string()));
    assert!(get_logs()
        .iter()
        .any(|l| l.contains(r#""event":"agent_revoked","data":{"agent":"agent-a","by":"owner"}"#)));

    // State is cleared before the key receipt runs.
    assert_eq!(c.agent_of_key(key(1)), None);
    assert_eq!(c.get_mandate("agent-a".into()), None);
    assert!(c.get_payees("agent-a".into()).is_empty());
    let rec = c.get_agent("agent-a".into()).unwrap();
    assert!(rec.revoked && rec.public_key.is_none());
    assert_eq!(
        rec.sweep_config.safe_address,
        "0x5afe000000000000000000000000000000000001"
    );

    // B is untouched.
    assert_eq!(c.agent_of_key(key(2)), Some("agent-b".to_string()));
    assert!(c.get_mandate("agent-b".into()).is_some());

    // The callback reports the key receipt; a failed DeleteKey is not an error.
    callback(true);
    let r = c.on_agent_key_deleted("agent-a".into());
    assert_eq!(
        r,
        RevokeResult {
            agent: "agent-a".into(),
            revoked: true,
            key_deleted: true
        }
    );
    callback(false);
    assert!(!c.on_agent_key_deleted("agent-a".into()).key_deleted);
}

#[test]
fn revoking_a_revoked_agent_returns_at_once() {
    let mut c = two_agents();
    call_from(WALLET);
    let _ = c.revoke("agent-a".into(), None);
    callback(true);
    c.on_agent_key_deleted("agent-a".into());
    call_from(WALLET);
    match c.revoke("agent-a".into(), None) {
        PromiseOrValue::Value(r) => assert_eq!(
            r,
            RevokeResult {
                agent: "agent-a".into(),
                revoked: true,
                key_deleted: false
            }
        ),
        PromiseOrValue::Promise(_) => panic!("no key action expected"),
    }
    assert_eq!(delete_key_receipt(), None);
    assert!(
        !get_logs().iter().any(|l| l.contains("agent_revoked")),
        "no second revoke event"
    );
    expect_err("ERR_UNKNOWN_AGENT", || c.revoke("nobody".into(), None));
}

#[test]
fn failed_delete_key_is_retried_by_the_next_revoke() {
    let mut c = two_agents();
    call_from(WALLET);
    let _ = c.revoke("agent-a".into(), None);
    callback(false);
    assert!(!c.on_agent_key_deleted("agent-a".into()).key_deleted);

    // The key is still on the account: revoking again retries DeleteKey, with no new event.
    call_from(WALLET);
    let r = c.revoke("agent-a".into(), None);
    assert!(matches!(r, PromiseOrValue::Promise(_)));
    drop(r);
    assert_eq!(delete_key_receipt(), Some(key(1).to_string()));
    assert!(!get_logs().iter().any(|l| l.contains("agent_revoked")));
    callback(true);
    assert!(c.on_agent_key_deleted("agent-a".into()).key_deleted);

    // Deleted: nothing left to retry.
    call_from(WALLET);
    assert!(matches!(
        c.revoke("agent-a".into(), None),
        PromiseOrValue::Value(_)
    ));
    assert_eq!(delete_key_receipt(), None);
}

#[test]
fn key_waiting_for_delete_key_cannot_go_to_a_new_agent() {
    let mut c = two_agents();
    call_from(WALLET);
    let _ = c.revoke("agent-a".into(), None);
    callback(false);
    c.on_agent_key_deleted("agent-a".into());
    // The key is still on the account and would map to the new agent (SEC-4).
    call_from(WALLET);
    expect_err("ERR_KEY_EXISTS", || {
        c.add_agent("agent-c".into(), key(1), sweep_config(), evm(), None)
    });
    assert_eq!(c.agent_of_key(key(1)), None);
}

#[test]
fn revoke_by_the_agent_itself() {
    let mut c = two_agents();
    agent_call(key(1));
    let r = c.revoke_self();
    assert!(matches!(r, PromiseOrValue::Promise(_)));
    drop(r); // near-sdk schedules a promise when it is dropped
    assert_eq!(delete_key_receipt(), Some(key(1).to_string()));
    assert!(get_logs().iter().any(|l| l.contains(r#""by":"agent""#)));
    assert_eq!(c.agent_of_key(key(1)), None);
    assert_eq!(c.get_mandate("agent-a".into()), None);
    assert!(c.get_agent("agent-a".into()).unwrap().revoked);
    // Only the caller: B keeps its key, mandate and payees.
    assert_eq!(c.agent_of_key(key(2)), Some("agent-b".to_string()));
    assert!(c.get_mandate("agent-b".into()).is_some());
    assert!(!c.get_agent("agent-b".into()).unwrap().revoked);
    // Its key no longer maps to an agent.
    agent_call(key(1));
    expect_err("ERR_UNKNOWN_AGENT_KEY", || c.revoke_self());
}

#[test]
fn revoke_self_needs_a_registered_agent_key() {
    let mut c = two_agents();
    call_at("someone.testnet", key(1), NOW, vec![]); // A's key, but signing for another account
    expect_err("ERR_NOT_AGENT_KEY", || c.revoke_self());
    agent_call(key(7));
    expect_err("ERR_UNKNOWN_AGENT_KEY", || c.revoke_self());
}

#[test]
fn agent_a_key_cannot_revoke_or_act_for_b() {
    let mut c = two_agents();
    // Agent calls take no agent argument: A's key resolves to A only.
    agent_call(key(1));
    assert_eq!(c.calling_agent(), "agent-a");
    // A cannot use the owner path for B.
    expect_err("ERR_NOT_OWNER", || c.revoke("agent-b".into(), None));
    // revoke_self with A's key revokes A, never B.
    let _ = c.revoke_self();
    assert!(!c.get_agent("agent-b".into()).unwrap().revoked);
    assert_eq!(c.agent_of_key(key(2)), Some("agent-b".to_string()));
}

#[test]
fn revoked_agent_takes_no_new_mandate_or_payee() {
    let mut c = two_agents();
    call_from(WALLET);
    let _ = c.revoke("agent-a".into(), None);
    call_from(WALLET);
    expect_err("ERR_AGENT_REVOKED", || {
        c.set_mandate("agent-a".into(), mandate(), None)
    });
    expect_err("ERR_AGENT_REVOKED", || {
        c.add_payee(
            "agent-a".into(),
            Payee::Sepa {
                iban: "DE89370400440532013000".into(),
            },
            None,
        )
    });
}

// ---------- C7: link_agent ----------

/// Passkey contract with agent-a (key 1), owner_nonce at 1 after add_agent.
fn link_agent_fixture() -> Contract {
    link_agent_fixture_with_evm(evm())
}

fn link_agent_fixture_with_evm(evm_address: EvmAddress) -> Contract {
    let mut c = new_passkey();
    call_from("anyone.testnet");
    let args = borsh::to_vec(&(
        "agent-a".to_string(),
        key(1),
        sweep_config(),
        evm_address.clone(),
    ))
    .unwrap();
    let a = Signing::new("add_agent", args, 1).sign();
    let _ = c.add_agent(
        "agent-a".into(),
        key(1),
        sweep_config(),
        evm_address,
        Some(a),
    );
    c
}

#[test]
fn link_agent_agent_key_is_rejected() {
    let mut c = link_agent_fixture();
    agent_call(key(1));
    expect_err("ERR_ASSERTION_REQUIRED", || {
        c.link_agent("agent-a".into(), None)
    });
}

#[test]
fn link_agent_owner_succeeds() {
    let mut c = link_agent_fixture();
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));
    assert!(c.get_agent("agent-a".into()).unwrap().linked);
    // A receipt for the MPC sign call was created.
    assert!(!get_created_receipts().is_empty());
}

#[test]
fn link_agent_rejects_second_call() {
    let mut c = link_agent_fixture();
    call_from("anyone.testnet");
    let args = borsh::to_vec(&("agent-a".to_string(),)).unwrap();
    let a = Signing::new("link_agent", args, 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));

    call_from("anyone.testnet");
    let args = borsh::to_vec(&("agent-a".to_string(),)).unwrap();
    let a = Signing::new("link_agent", args, 3).sign();
    expect_err("ERR_ALREADY_LINKED", || {
        c.link_agent("agent-a".into(), Some(a))
    });
}

#[test]
fn link_agent_rejects_unknown_agent() {
    let mut c = link_agent_fixture();
    call_from("anyone.testnet");
    let args = borsh::to_vec(&("nobody".to_string(),)).unwrap();
    let a = Signing::new("link_agent", args, 2).sign();
    expect_err("ERR_UNKNOWN_AGENT", || {
        c.link_agent("nobody".into(), Some(a))
    });
}

#[test]
fn link_agent_revoked_agent_rejected() {
    let mut c = link_agent_fixture();
    call_from("anyone.testnet");
    let a = Signing::new("revoke", agent_args("agent-a"), 2).sign();
    let _ = c.revoke("agent-a".into(), Some(a));

    call_from("anyone.testnet");
    let args = borsh::to_vec(&("agent-a".to_string(),)).unwrap();
    let a = Signing::new("link_agent", args, 3).sign();
    expect_err("ERR_AGENT_REVOKED", || {
        c.link_agent("agent-a".into(), Some(a))
    });
}

// ---------- C7 callback tests ----------

#[test]
fn on_link_signature_success_keeps_linked() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));

    mpc_callback(mpc_link_ok());
    let key = link_reservation_key(&c, "agent-a");
    let res = c.on_link_signature(key);
    assert_eq!(res.status, RequestStatus::Signed);
    assert!(res.signature.is_some());
    assert!(c.get_agent("agent-a".into()).unwrap().linked);
}

#[test]
fn on_link_signature_failure_resets_linked() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));

    mpc_callback(PromiseResult::Failed);
    let key = link_reservation_key(&c, "agent-a");
    let res = c.on_link_signature(key.clone());
    assert_eq!(res.status, RequestStatus::Unknown);
    assert!(res.signature.is_none());
    assert!(!c.get_agent("agent-a".into()).unwrap().linked);
    assert_one_agent_unlinked("agent-a", &key);
}

#[test]
fn on_link_signature_wrong_key_resets_linked() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));

    mpc_callback(mpc_link_wrong_key());
    let key = link_reservation_key(&c, "agent-a");
    let res = c.on_link_signature(key.clone());
    assert_eq!(res.status, RequestStatus::Unknown);
    assert!(res.signature.is_none());
    assert!(!c.get_agent("agent-a".into()).unwrap().linked);
    assert_one_agent_unlinked("agent-a", &key);
}

#[test]
fn link_agent_retry_after_failure() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));

    // Callback fails → linked resets.
    mpc_callback(PromiseResult::Failed);
    let key = link_reservation_key(&c, "agent-a");
    let _ = c.on_link_signature(key);
    assert!(!c.get_agent("agent-a".into()).unwrap().linked);

    // Owner retries.
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 3).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));
    assert!(c.get_agent("agent-a".into()).unwrap().linked);
}

#[test]
fn link_agent_second_call_after_success_rejected() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));

    // Callback succeeds.
    mpc_callback(mpc_link_ok());
    let key = link_reservation_key(&c, "agent-a");
    let res = c.on_link_signature(key);
    assert_eq!(res.status, RequestStatus::Signed);
    assert!(c.get_agent("agent-a".into()).unwrap().linked);

    // Second call rejected.
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 3).sign();
    expect_err("ERR_ALREADY_LINKED", || {
        c.link_agent("agent-a".into(), Some(a))
    });
}

#[test]
fn link_after_expire_then_valid_mpc_records_signed() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));

    // Advance past MPC timeout (300 s), then anyone expires the pending link reservation.
    call_at("anyone.testnet", key(200), NOW + 600, vec![]);
    let key = link_reservation_key(&c, "agent-a");
    c.expire_pending(key.clone());

    // Late valid MPC signature arrives.
    mpc_callback(mpc_link_ok());
    let res = c.on_link_signature(key);
    assert_eq!(res.status, RequestStatus::Signed);
    assert!(res.signature.is_some());
    assert!(c.get_agent("agent-a".into()).unwrap().linked);
}

/// `expire_pending` leaves the link reservation `Unknown` while the agent is still linked;
/// a late `bad` callback then resets `linked` once, keeps `Unknown`, and the owner can retry.
fn link_after_expire_then_bad_callback_resets_linked(bad: PromiseResult) {
    let mut c = link_agent_fixture_with_evm(link_evm());
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));
    assert!(c.get_agent("agent-a".into()).unwrap().linked);

    // Advance past MPC timeout, then anyone expires the pending link reservation.
    call_at("anyone.testnet", key(200), NOW + 600, vec![]);
    let key = link_reservation_key(&c, "agent-a");
    c.expire_pending(key.clone());
    assert_eq!(
        c.get_request(key.clone()).unwrap().status,
        RequestStatus::Unknown
    );
    assert!(c.get_agent("agent-a".into()).unwrap().linked);

    // Callback fails → linked resets, owner can retry.
    mpc_callback(bad);
    let res = c.on_link_signature(key.clone());
    assert_eq!(res.status, RequestStatus::Unknown);
    assert!(res.signature.is_none());
    assert!(!c.get_agent("agent-a".into()).unwrap().linked);
    assert!(
        !get_logs().iter().any(|l| l.contains("request_unknown")),
        "no second request_unknown"
    );
    assert_one_agent_unlinked("agent-a", &key);

    // Owner retries and succeeds.
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 3).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));
    assert!(c.get_agent("agent-a".into()).unwrap().linked);
}

#[test]
fn link_after_expire_then_failed_callback_resets_linked() {
    link_after_expire_then_bad_callback_resets_linked(PromiseResult::Failed);
}

#[test]
fn link_after_expire_then_wrong_key_callback_resets_linked() {
    link_after_expire_then_bad_callback_resets_linked(mpc_link_wrong_key());
}

/// Expire a link, owner resolves it to `outcome`, then a failed and a wrong-key callback
/// arrive: the terminal status, `linked` and the event log stay untouched (used for `Spent`).
fn link_resolved_then_late_bad_callbacks(outcome: ResolveOutcome, expected: RequestStatus) {
    let mut c = link_agent_fixture_with_evm(link_evm());
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));

    call_at("anyone.testnet", key(200), NOW + 600, vec![]);
    let key = link_reservation_key(&c, "agent-a");
    c.expire_pending(key.clone());

    call_from("anyone.testnet");
    let args = borsh::to_vec(&(&key, &outcome)).unwrap();
    let a = Signing::new("resolve_reservation", args, 3).sign();
    c.resolve_reservation(key.clone(), outcome, Some(a));
    let linked = c.get_agent("agent-a".into()).unwrap().linked;

    for result in [PromiseResult::Failed, mpc_link_wrong_key()] {
        mpc_callback(result);
        let res = c.on_link_signature(key.clone());
        assert_eq!(res.status, expected);
        assert!(res.signature.is_none());
        assert_eq!(c.get_request(key.clone()).unwrap().status, expected);
        assert_eq!(c.get_agent("agent-a".into()).unwrap().linked, linked);
        assert!(
            !get_logs().iter().any(|l| l.contains("request_unknown")),
            "no request_unknown after a terminal status"
        );
        assert!(!get_logs().iter().any(|l| l.contains("agent_unlinked")));
    }
}

/// `Released` alone keeps `linked` (a late valid signature can still land on it); a late
/// `bad` callback then resets `linked`, keeps `Released`, and the owner can link again.
fn link_released_then_late_bad_callback_resets_linked(bad: PromiseResult) {
    let mut c = link_agent_fixture_with_evm(link_evm());
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));

    call_at("anyone.testnet", key(200), NOW + 600, vec![]);
    let key = link_reservation_key(&c, "agent-a");
    c.expire_pending(key.clone());

    call_from("anyone.testnet");
    let args = borsh::to_vec(&(&key, &ResolveOutcome::Released)).unwrap();
    let a = Signing::new("resolve_reservation", args, 3).sign();
    c.resolve_reservation(key.clone(), ResolveOutcome::Released, Some(a));
    assert!(c.get_agent("agent-a".into()).unwrap().linked);

    mpc_callback(bad);
    let res = c.on_link_signature(key.clone());
    assert_eq!(res.status, RequestStatus::Released);
    assert!(res.signature.is_none());
    assert_eq!(
        c.get_request(key.clone()).unwrap().status,
        RequestStatus::Released
    );
    assert!(!c.get_agent("agent-a".into()).unwrap().linked);
    assert!(
        !get_logs().iter().any(|l| l.contains("request_unknown")),
        "no request_unknown after a terminal status"
    );
    assert_one_agent_unlinked("agent-a", &key);

    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 4).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));
    assert!(c.get_agent("agent-a".into()).unwrap().linked);
}

#[test]
fn link_released_then_late_failed_callback_resets_linked() {
    link_released_then_late_bad_callback_resets_linked(PromiseResult::Failed);
}

#[test]
fn link_released_then_late_wrong_key_callback_resets_linked() {
    link_released_then_late_bad_callback_resets_linked(mpc_link_wrong_key());
}

#[test]
fn link_released_then_late_valid_callback_records_signed() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 2).sign();
    let _ = c.link_agent("agent-a".into(), Some(a));

    call_at("anyone.testnet", key(200), NOW + 600, vec![]);
    let key = link_reservation_key(&c, "agent-a");
    c.expire_pending(key.clone());

    call_from("anyone.testnet");
    let args = borsh::to_vec(&(&key, &ResolveOutcome::Released)).unwrap();
    let a = Signing::new("resolve_reservation", args, 3).sign();
    c.resolve_reservation(key.clone(), ResolveOutcome::Released, Some(a));

    mpc_callback(mpc_link_ok());
    let res = c.on_link_signature(key);
    assert_eq!(res.status, RequestStatus::Signed);
    assert!(c.get_agent("agent-a".into()).unwrap().linked);

    call_from("anyone.testnet");
    let a = Signing::new("link_agent", agent_args("agent-a"), 4).sign();
    expect_err("ERR_ALREADY_LINKED", || {
        c.link_agent("agent-a".into(), Some(a))
    });
}

#[test]
fn link_spent_then_late_bad_callbacks_leave_it_spent() {
    link_resolved_then_late_bad_callbacks(ResolveOutcome::Spent, RequestStatus::Spent);
}

#[test]
fn link_prefix_is_reserved_for_owner_link_requests() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    agent_call(key(1));
    expect_err("ERR_INVALID_REQUEST_ID", || {
        c.request_signature("link-1".into(), Shape::Link)
    });
    agent_call(key(1));
    expect_err("ERR_INVALID_REQUEST_ID", || {
        c.sweep(
            "agent-a".into(),
            Token::Usdc,
            U128(100),
            "link-1".into(),
            None,
            None,
        )
    });
    call_from("anyone.testnet");
    let args = borsh::to_vec(&(
        &AgentId::from("agent-a"),
        &Token::Usdc,
        &U128(100),
        &"link-1".to_string(),
        &None::<EvmTxParams>,
    ))
    .unwrap();
    let a = Signing::new("sweep", args, 2).sign();
    expect_err("ERR_INVALID_REQUEST_ID", || {
        c.sweep(
            "agent-a".into(),
            Token::Usdc,
            U128(100),
            "link-1".into(),
            None,
            Some(a),
        )
    });
}

// --- C4b sweep ---

#[test]
fn agent_sweep_creates_reservation() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    assert_eq!(c.list_requests("agent-a".into(), 0, 10).len(), 0);
    agent_call(key(1));
    let _ = c.sweep(
        "agent-a".into(),
        Token::Usdc,
        U128(100),
        "sweep-001".into(),
        None,
        None,
    );
    let reqs = c.list_requests("agent-a".into(), 0, 10);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].key.request_id, "sweep-001");
    assert_eq!(reqs[0].shape, ShapeKind::Sweep);
}

#[test]
fn agent_sweep_rejects_second_pending() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    agent_call(key(1));
    let _ = c.sweep(
        "agent-a".into(),
        Token::Usdc,
        U128(100),
        "sweep-001".into(),
        None,
        None,
    );
    expect_err("ERR_SWEEP_PENDING", || {
        agent_call(key(1));
        c.sweep(
            "agent-a".into(),
            Token::Usdc,
            U128(100),
            "sweep-002".into(),
            None,
            None,
        )
    });
}

#[test]
fn agent_sweep_wrong_agent_rejected() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    agent_call(key(1));
    expect_err("ERR_SWEEP_CALLER_NOT_ALLOWED", || {
        c.sweep(
            "agent-b".into(),
            Token::Usdc,
            U128(100),
            "sweep-001".into(),
            None,
            None,
        )
    });
}

#[test]
fn agent_sweep_unmapped_key_rejected() {
    // On the contract account with a key that maps to no agent: past the predecessor
    // check, so calling_agent answers ERR_UNKNOWN_AGENT_KEY.
    let mut c = link_agent_fixture_with_evm(link_evm());
    agent_call(key(7));
    expect_err("ERR_UNKNOWN_AGENT_KEY", || {
        c.sweep(
            "agent-a".into(),
            Token::Usdc,
            U128(100),
            "sweep-001".into(),
            None,
            None,
        )
    });
}

#[test]
fn sweep_after_revoke_works_with_owner() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    // Owner revokes agent-a
    call_from("anyone.testnet");
    let a = Signing::new("revoke", agent_args("agent-a"), 2).sign();
    let _ = c.revoke("agent-a".into(), Some(a));
    assert!(c.get_agent("agent-a".into()).unwrap().revoked);

    // Owner can still sweep the revoked agent
    call_from("anyone.testnet");
    let sweep_args = borsh::to_vec(&(
        "agent-a".to_string(),
        Token::Usdc,
        U128(100),
        "sweep-r1".to_string(),
        Option::<EvmTxParams>::None,
    ))
    .unwrap();
    let a = Signing::new("sweep", sweep_args, 3).sign();
    let _ = c.sweep(
        "agent-a".into(),
        Token::Usdc,
        U128(100),
        "sweep-r1".into(),
        None,
        Some(a),
    );
    let reqs = c.list_requests("agent-a".into(), 0, 10);
    assert!(reqs.iter().any(|r| r.key.request_id == "sweep-r1"));
}

#[test]
fn sweep_second_after_callback_succeeds() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    agent_call(key(1));
    let _ = c.sweep(
        "agent-a".into(),
        Token::Usdc,
        U128(100),
        "sw1".into(),
        None,
        None,
    );

    // Callback (any outcome) should clean up pending_sweeps
    mpc_callback(PromiseResult::Failed);
    let key1 = RequestKey {
        agent: "agent-a".into(),
        caller: Caller::Agent,
        request_id: "sw1".into(),
    };
    c.on_signature(key1);

    // Second sweep with different request_id should succeed (pending_sweeps was cleaned)
    agent_call(key(1));
    let _ = c.sweep(
        "agent-a".into(),
        Token::Usdc,
        U128(200),
        "sw2".into(),
        None,
        None,
    );
    let reqs = c.list_requests("agent-a".into(), 0, 10);
    assert!(reqs.iter().any(|r| r.key.request_id == "sw2"));
}

#[test]
fn sweep_second_after_signed_callback_succeeds() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    agent_call(key(1));
    let _ = c.sweep(
        "agent-a".into(),
        Token::Usdc,
        U128(100),
        "sa1".into(),
        None,
        None,
    );

    // Get the sweep digest from the reservation and sign it with the test key (LINK_SK_BYTES).
    let reqs = c.list_requests("agent-a".into(), 0, 10);
    let digest_hex = reqs
        .iter()
        .find(|r| r.key.request_id == "sa1")
        .unwrap()
        .digest
        .clone();
    let digest_bytes: [u8; 32] = hex::decode(digest_hex.strip_prefix("0x").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    mpc_callback(mpc_sweep_ok(digest_bytes));
    let key1 = RequestKey {
        agent: "agent-a".into(),
        caller: Caller::Agent,
        request_id: "sa1".into(),
    };
    let res = c.on_signature(key1);
    assert_eq!(res.status, RequestStatus::Signed);

    // Second sweep with different request_id should succeed
    agent_call(key(1));
    let _ = c.sweep(
        "agent-a".into(),
        Token::Usdc,
        U128(200),
        "sa2".into(),
        None,
        None,
    );
    let reqs2 = c.list_requests("agent-a".into(), 0, 10);
    assert!(reqs2.iter().any(|r| r.key.request_id == "sa2"));
}

#[test]
fn wallet_owner_sweep_succeeds_with_one_yocto() {
    let mut c = new_wallet();
    call_from(WALLET);
    let _ = c.add_agent("agent-w".into(), key(10), sweep_config(), link_evm(), None);
    callback(true);
    assert!(c.on_agent_key_added("agent-w".into(), key(10)));

    // Wallet owner calls sweep with assertion: None, from owner account, with 1 yocto.
    call_from(WALLET);
    let _ = c.sweep(
        "agent-w".into(),
        Token::Usdc,
        U128(50),
        "ws1".into(),
        None,
        None,
    );
    let reqs = c.list_requests("agent-w".into(), 0, 10);
    assert_eq!(reqs.len(), 1);
}

#[test]
fn wallet_owner_sweep_without_deposit_is_rejected() {
    let mut c = new_wallet();
    call_from(WALLET);
    let _ = c.add_agent("agent-w".into(), key(10), sweep_config(), link_evm(), None);
    callback(true);
    assert!(c.on_agent_key_added("agent-w".into(), key(10)));

    // Try sweep with 0 deposit from wallet owner — should fail
    let ctx = VMContextBuilder::new()
        .current_account_id(acc(CONTRACT))
        .predecessor_account_id(acc(WALLET))
        .signer_account_id(acc(WALLET))
        .signer_account_pk(key(200))
        .attached_deposit(NearToken::from_yoctonear(0))
        .block_timestamp(NOW * 1_000_000_000)
        .build();
    testing_env!(
        ctx,
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![]
    );
    expect_err("ERR_NOT_OWNER", || {
        let _ = c.sweep(
            "agent-w".into(),
            Token::Usdc,
            U128(50),
            "ws1".into(),
            None,
            None,
        );
    });
}

#[test]
fn wallet_owner_sweep_has_owner_caller_and_pending_status() {
    let mut c = new_wallet();
    call_from(WALLET);
    let _ = c.add_agent("agent-w".into(), key(10), sweep_config(), link_evm(), None);
    callback(true);
    assert!(c.on_agent_key_added("agent-w".into(), key(10)));

    call_from(WALLET);
    let _ = c.sweep(
        "agent-w".into(),
        Token::Usdc,
        U128(50),
        "ws1".into(),
        None,
        None,
    );
    let reqs = c.list_requests("agent-w".into(), 0, 10);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].key.caller, Caller::Owner);
    assert_eq!(reqs[0].status, RequestStatus::Pending);
}

#[test]
fn sweep_rejects_third_account() {
    let mut c = link_agent_fixture_with_evm(link_evm());
    // A random account (not owner, not relayer, not the agent) calling sweep with assertion: None.
    call_from("eve.testnet");
    expect_err("ERR_SWEEP_CALLER_NOT_ALLOWED", || {
        let _ = c.sweep(
            "agent-a".into(),
            Token::Usdc,
            U128(100),
            "sweep-001".into(),
            None,
            None,
        );
    });
}

// ---------- views ----------

#[test]
fn views() {
    let c = two_agents();
    let all = c.list_agents(0, 10);
    assert_eq!(
        all.iter().map(|r| r.agent.as_str()).collect::<Vec<_>>(),
        ["agent-a", "agent-b"]
    );
    assert_eq!(c.list_agents(1, 10).len(), 1);
    assert!(c.get_agent("nobody".into()).is_none());
    assert!(c.get_budget("nobody".into(), Rail::Sepa).is_none());
    assert!(c.list_requests("agent-a".into(), 0, 10).is_empty());
    let cfg = c.get_config();
    assert_eq!(cfg.network, NETWORK);
    assert_eq!(cfg.mpc_contract, acc("v1.signer-prod.testnet"));
}

#![cfg(feature = "patched-tls")]

use btls::{hash::MessageDigest, pkey::PKey, sign::Verifier};
use fingerprint_bridge::crypto_ed448::{register, verify};
use foreign_types::ForeignType;
use std::ffi::{c_int, c_void};

// Public key, message and signature only, from RFC 8032, section 7.4.
// These independent known-answer vectors do not use this provider to sign.
const PUBLIC_EMPTY: &str = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
const SIGNATURE_EMPTY: &str = "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600";
const PUBLIC_ONE: &str = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480";
const SIGNATURE_ONE: &str = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00";
const SIGNATURE_CONTEXT: &str = "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00";

fn bytes(hexadecimal: &str) -> Vec<u8> {
    hex::decode(hexadecimal).unwrap()
}

fn spki(public: &[u8], params: &[u8]) -> Vec<u8> {
    assert!(public.len() + params.len() < 100);
    let mut der = vec![
        0x30,
        (10 + public.len() + params.len()) as u8,
        0x30,
        (5 + params.len()) as u8,
        0x06,
        0x03,
        0x2b,
        0x65,
        0x71,
    ];
    der.extend_from_slice(params);
    der.extend_from_slice(&[0x03, (public.len() + 1) as u8, 0]);
    der.extend_from_slice(public);
    der
}

fn native_verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key = PKey::public_key_from_der(&spki(public, &[])).unwrap();
    let mut verifier = Verifier::new_without_digest(&key).unwrap();
    verifier.verify_oneshot(signature, message).unwrap_or(false)
}

#[test]
fn ed448_rfc8032_pure_signatures_match_provider_and_native_evp() {
    assert!(register());
    for (public, message, signature) in [
        (PUBLIC_EMPTY, &b""[..], SIGNATURE_EMPTY),
        (PUBLIC_ONE, &b"\x03"[..], SIGNATURE_ONE),
    ] {
        let public = bytes(public);
        let signature = bytes(signature);
        assert!(verify(&public, message, &signature));
        assert!(native_verify(&public, message, &signature));
        assert!(!verify(&public, b"wrong message", &signature));
        assert!(!native_verify(&public, b"wrong message", &signature));
        for byte in [0, 56, 57, 113] {
            let mut altered = signature.clone();
            altered[byte] ^= 1;
            assert!(!verify(&public, message, &altered));
            assert!(!native_verify(&public, message, &altered));
        }
    }
}

#[test]
fn ed448_rejects_context_prehash_and_noncanonical_signatures() {
    assert!(register());
    let public = bytes(PUBLIC_ONE);
    let context_signature = bytes(SIGNATURE_CONTEXT);
    // A valid Ed448 signature with context "foo" is invalid under PureEd448.
    assert!(!verify(&public, b"\x03", &context_signature));
    assert!(!native_verify(&public, b"\x03", &context_signature));
    // RFC 8032, section 7.5, Ed448ph("abc") is not PureEd448("abc").
    let ph_public = bytes("259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880");
    let ph_sig = bytes("822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00");
    assert!(!verify(&ph_public, b"abc", &ph_sig));
    assert!(!native_verify(&ph_public, b"abc", &ph_sig));

    let signature = bytes(SIGNATURE_ONE);
    let mut invalid = vec![signature[..113].to_vec()];
    let mut too_long = signature.clone();
    too_long.push(0);
    invalid.push(too_long);
    let mut noncanonical_r = signature.clone();
    noncanonical_r[..57].fill(0xff);
    invalid.push(noncanonical_r);
    let mut scalar_at_order = signature.clone();
    scalar_at_order[57..].copy_from_slice(&bytes("f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00"));
    invalid.push(scalar_at_order);
    let mut nonzero_scalar_last_byte = signature;
    nonzero_scalar_last_byte[113] = 1;
    invalid.push(nonzero_scalar_last_byte);
    for invalid_signature in invalid {
        assert!(!verify(&public, b"\x03", &invalid_signature));
        assert!(!native_verify(&public, b"\x03", &invalid_signature));
    }
}

#[test]
fn ed448_rejects_weak_and_noncanonical_public_keys() {
    assert!(register());
    let mut identity = [0u8; 57];
    identity[0] = 1;
    let low_order = [0u8; 57];
    // Identity R and zero S make the cofactored equation vacuous for a weak
    // public key. This must be rejected before signature verification.
    let mut forged = [0u8; 114];
    forged[0] = 1;
    for weak in [identity, low_order] {
        let key = crrl::ed448::PublicKey::decode(&weak).unwrap();
        assert!(key.verify_raw(&forged, b"arbitrary authenticated data"));
        assert!(!verify(&weak, b"arbitrary authenticated data", &forged));
        assert!(!native_verify(
            &weak,
            b"arbitrary authenticated data",
            &forged
        ));
    }
    let torsion = crrl::ed448::Point::decode(&low_order).unwrap();
    let mixed = (crrl::ed448::Point::BASE + torsion).encode();
    let mixed_key = crrl::ed448::PublicKey::decode(&mixed).unwrap();
    assert_eq!(mixed_key.point.is_in_subgroup(), 0);
    assert!(!verify(&mixed, b"", &bytes(SIGNATURE_EMPTY)));
    assert!(!native_verify(&mixed, b"", &bytes(SIGNATURE_EMPTY)));
    let mut noncanonical = bytes(PUBLIC_EMPTY);
    noncanonical[56] |= 1; // Ed448's final byte has only the sign bit.
    assert!(!verify(&noncanonical, b"", &bytes(SIGNATURE_EMPTY)));
    assert!(!native_verify(&noncanonical, b"", &bytes(SIGNATURE_EMPTY)));
    assert!(!verify(&[0xff; 57], b"", &forged));
    assert!(!verify(&identity[..56], b"", &forged));
}

#[test]
fn ed448_spki_requires_absent_parameters_and_exact_encoding() {
    assert!(register());
    let public = bytes(PUBLIC_EMPTY);
    let der = spki(&public, &[]);
    let key = PKey::public_key_from_der(&der).unwrap();
    assert_eq!(key.id().as_raw(), 960); // NID_ED448; distinct from X448.
    assert_eq!(key.bits(), 446); // EVP documents EC group-order bit length.
    assert_eq!(key.size(), 114);
    assert_eq!(key.public_key_to_der().unwrap(), der);
    let mut raw = [0u8; 57];
    assert_eq!(key.raw_public_key(&mut raw).unwrap(), public);
    for params in [&b"\x05\x00"[..], &b"\x04\x00"[..]] {
        assert!(PKey::public_key_from_der(&spki(&public, params)).is_err());
    }
    assert!(PKey::public_key_from_der(&spki(&public[..56], &[])).is_err());
    let mut longer = public;
    longer.push(0);
    assert!(PKey::public_key_from_der(&spki(&longer, &[])).is_err());
    let mut invalid_padding = der.clone();
    invalid_padding[11] = 1;
    assert!(PKey::public_key_from_der(&invalid_padding).is_err());
    let mut wrong_oid = der;
    wrong_oid[8] = 0x6f; // X448 OID must not be accepted as Ed448.
    assert!(PKey::public_key_from_der(&wrong_oid).is_err());
    assert!(Verifier::new(MessageDigest::sha512(), &key).is_err());
}

type VerifyCallback = unsafe extern "C" fn(*const u8, *const u8, usize, *const u8) -> c_int;
extern "C" {
    fn EVP_set_bridge_ed448_verify_callback(callback: Option<VerifyCallback>) -> c_int;
    fn EVP_bridge_ed448_verify_available() -> c_int;
    fn EVP_PKEY_CTX_new(key: *mut c_void, engine: *mut c_void) -> *mut c_void;
    fn EVP_PKEY_sign_init(ctx: *mut c_void) -> c_int;
    fn EVP_PKEY_CTX_free(ctx: *mut c_void);
}

unsafe extern "C" fn always_accept(_: *const u8, _: *const u8, _: usize, _: *const u8) -> c_int {
    1
}

#[test]
fn ed448_provider_cannot_be_replaced_or_used_for_signing() {
    assert!(register());
    let key = PKey::public_key_from_der(&spki(&bytes(PUBLIC_EMPTY), &[])).unwrap();
    // SAFETY: native setters do not invoke the candidate pointer, and reject
    // both replacement and unregistration once the real provider is installed.
    unsafe {
        assert_eq!(EVP_set_bridge_ed448_verify_callback(Some(always_accept)), 0);
        assert_eq!(EVP_set_bridge_ed448_verify_callback(None), 0);
        assert_eq!(EVP_bridge_ed448_verify_available(), 1);
        let ctx = EVP_PKEY_CTX_new(key.as_ptr().cast(), std::ptr::null_mut());
        assert!(!ctx.is_null());
        let signed = EVP_PKEY_sign_init(ctx);
        EVP_PKEY_CTX_free(ctx);
        assert_eq!(signed, 0);
    }
    assert!(!native_verify(&bytes(PUBLIC_EMPTY), b"", &[0; 114]));
}

#[test]
fn ed448_native_without_provider_fails_closed() {
    const MARKER: &str = "FINGERPRINT_BRIDGE_TEST_ED448_UNREGISTERED";
    if std::env::var_os(MARKER).is_some() {
        // A fresh process proves absence cannot accidentally become support.
        // SAFETY: the getter has no arguments or side effects.
        assert_eq!(unsafe { EVP_bridge_ed448_verify_available() }, 0);
        assert!(!native_verify(
            &bytes(PUBLIC_EMPTY),
            b"",
            &bytes(SIGNATURE_EMPTY)
        ));
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "ed448_native_without_provider_fails_closed",
            "--nocapture",
        ])
        .env(MARKER, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

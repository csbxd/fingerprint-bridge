use crate::fingerprint::{grease, TlsHello};
use anyhow::{ensure, Result};
use btls::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ExtensionType, SslCipher, SslConnector,
    SslMethod, SslOptions, SslSignatureAlgorithm, SslVersion,
};
use std::path::Path;

// Complete kExtensions table in the pinned btls-sys 0.5.6 backend. Supplying
// all identifiers avoids its random remainder ordering (and the off-by-one
// seed read in that path). This orders extensions; it does not enable them.
const BACKEND_EXTENSIONS: &[u16] = &[
    0, 65037, 23, 65281, 10, 11, 35, 16, 5, 13, 13172, 18, 30032, 14, 51, 45, 42, 43, 44, 57,
    65445, 27, 34, 17613, 17513, 47, 35387, 51764, 28,
];
fn extension_order(incoming: &[u16]) -> Vec<ExtensionType> {
    let mut order = Vec::new();
    for id in incoming.iter().chain(BACKEND_EXTENSIONS) {
        if BACKEND_EXTENSIONS.contains(id) && !order.contains(id) {
            order.push(*id);
        }
    }
    order.into_iter().map(ExtensionType::from).collect()
}

struct Brotli;
impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        std::io::copy(&mut brotli::Decompressor::new(input, 4096), output)?;
        Ok(())
    }
}
struct Zlib;
impl CertificateCompressor for Zlib {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        std::io::copy(&mut flate2::read::ZlibDecoder::new(input), output)?;
        Ok(())
    }
}
fn group(id: u16) -> Option<&'static str> {
    match id {
        23 => Some("P-256"),
        24 => Some("P-384"),
        25 => Some("P-521"),
        29 => Some("X25519"),
        4588 => Some("X25519MLKEM768"),
        #[cfg(feature = "patched-tls")]
        4587 => Some("SecP256r1MLKEM768"),
        #[cfg(feature = "patched-tls")]
        4589 => Some("SecP384r1MLKEM1024"),
        25497 => Some("X25519Kyber768Draft00"),
        256 => Some("ffdhe2048"),
        257 => Some("ffdhe3072"),
        _ => None,
    }
}
#[cfg(not(feature = "patched-tls"))]
fn share(id: u16) -> Option<btls::ssl::KeyShare> {
    use btls::ssl::KeyShare;
    match id {
        23 => Some(KeyShare::P256),
        24 => Some(KeyShare::P384),
        25 => Some(KeyShare::P521),
        29 => Some(KeyShare::X25519),
        4588 => Some(KeyShare::X25519_MLKEM768),
        25497 => Some(KeyShare::X25519_KYBER768_DRAFT00),
        256 => Some(KeyShare::FFDHE2048),
        257 => Some(KeyShare::FFDHE3072),
        _ => None,
    }
}

/// Match the origin's negotiated version on the incoming connection.
/// btls's historical Mozilla v4 profile sets NO_TLSV1_3 explicitly.
pub fn server_builder(version: SslVersion) -> Result<btls::ssl::SslAcceptorBuilder> {
    ensure!(
        version == SslVersion::TLS1_2 || version == SslVersion::TLS1_3,
        "unsupported negotiated origin TLS version"
    );
    let mut builder = btls::ssl::SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.clear_options(SslOptions::NO_TLSV1_3);
    builder.set_min_proto_version(Some(version))?;
    builder.set_max_proto_version(Some(version))?;
    Ok(builder)
}

/// Configure from observed wire features, never from User-Agent or an OS guess.
/// Unsupported features remain visible in the measured outbound comparison.
pub fn mirror(
    hello: &TlsHello,
    host: &str,
    ca: Option<&Path>,
) -> Result<(btls::ssl::Ssl, Vec<String>)> {
    let mut b = SslConnector::builder(SslMethod::tls())?;
    let mut limitations = vec![];
    if let Some(ca) = ca {
        b.set_ca_file(ca)?;
    }
    let only_tls13 = hello.supported_versions.contains(&0x0304)
        && !hello
            .supported_versions
            .iter()
            .any(|version| !grease(*version) && *version < 0x0304);
    b.set_min_proto_version(Some(if only_tls13 {
        SslVersion::TLS1_3
    } else {
        SslVersion::TLS1_2
    }))?;
    if !hello.supported_versions.contains(&0x0304) {
        b.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    }
    let mut ciphers = vec![];
    for id in &hello.ciphers {
        if grease(*id) || *id == 0xff {
            continue;
        }
        // ALL is a policy alias, not a capability catalog: it excludes 0xc027
        // and 3DES even when explicitly offered by this client and supported.
        if let Some(cipher) = SslCipher::from_value(*id) {
            ciphers.push(cipher.name().to_string())
        } else {
            limitations.push(format!("unsupported cipher {id}"))
        }
    }
    ensure!(!ciphers.is_empty(), "no supported client cipher suites");
    b.set_preserve_tls13_cipher_list(true);
    b.set_strict_cipher_list(&ciphers.join(":"))?;
    b.set_grease_enabled(
        hello
            .ciphers
            .iter()
            .chain(&hello.extensions)
            .any(|v| grease(*v)),
    );
    let mut groups = vec![];
    for id in &hello.groups {
        if grease(*id) {
            continue;
        }
        if let Some(g) = group(*id) {
            groups.push(g)
        } else {
            limitations.push(format!("unsupported group {id}"))
        }
    }
    if !groups.is_empty() {
        b.set_curves_list(&groups.join(":"))?;
    }
    const SIGNATURES: &[u16] = &[
        0x0201, 0x0203, 0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
        0x0807,
    ];
    let mut signatures = vec![];
    for id in &hello.signature_algorithms {
        if grease(*id) {
            continue;
        }
        if SIGNATURES.contains(id) {
            signatures.push(SslSignatureAlgorithm::from(*id));
        } else {
            limitations.push(format!("unsupported signature algorithm {id}"));
        }
    }
    if !signatures.is_empty() {
        b.set_verify_algorithm_prefs(&signatures)?;
    }
    let mut alpn = vec![];
    for p in &hello.alpn {
        let p = hex::decode(p)?;
        ensure!(p == b"h2" || p == b"http/1.1", "unsupported ALPN");
        alpn.push(p.len() as u8);
        alpn.extend(p);
    }
    if !alpn.is_empty() {
        b.set_alpn_protos(&alpn)?;
    }
    if hello.extensions.contains(&5) {
        b.enable_ocsp_stapling();
    }
    if hello.extensions.contains(&18) {
        b.enable_signed_cert_timestamps();
    }
    if !hello.extensions.contains(&35) {
        b.set_options(SslOptions::NO_TICKET);
    }
    if !hello.extensions.contains(&65281) {
        b.set_options(SslOptions::NO_RENEGOTIATION);
    }
    if !hello.extensions.contains(&45) {
        b.set_options(SslOptions::NO_PSK_DHE_KE);
    }
    if !cfg!(feature = "patched-tls") && hello.ciphers.contains(&0xff) {
        limitations.push("renegotiation SCSV cannot be emitted by this backend".into());
    }
    for id in &hello.cert_compression {
        match id {
            1 => b.add_certificate_compression_algorithm(Zlib)?,
            2 => b.add_certificate_compression_algorithm(Brotli)?,
            _ => limitations.push(format!("unsupported certificate compression {id}")),
        }
    }
    // Only the backend's supported extension identifiers are passed to its API.
    const KNOWN: &[u16] = &[
        0, 5, 10, 11, 13, 16, 18, 21, 23, 27, 28, 34, 35, 41, 42, 43, 44, 45, 47, 51, 17513, 17613,
        65037, 65281,
    ];
    let order = extension_order(&hello.extensions);
    b.set_extension_permutation(&order)?;
    for id in &hello.extensions {
        if !grease(*id) && !KNOWN.contains(id) {
            limitations.push(format!("unsupported extension {id}"))
        }
    }
    let connector = b.build();
    let ssl = connector.configure()?.into_ssl(host)?;
    #[cfg(not(feature = "patched-tls"))]
    let mut ssl = ssl;
    #[cfg(feature = "patched-tls")]
    {
        use foreign_types::ForeignType;
        unsafe extern "C" {
            fn SSL_set_bridge_profile(
                ssl: *mut std::ffi::c_void,
                ciphers: *const u16,
                count: usize,
                padding: std::ffi::c_int,
            ) -> std::ffi::c_int;
        }
        let order: Vec<_> = hello
            .ciphers
            .iter()
            .copied()
            .filter(|id| grease(*id) || *id == 0xff || SslCipher::from_value(*id).is_some())
            .collect();
        // The backend validates enabled suites and copies the slice. It creates
        // fresh cryptographic state and hashes the actual emitted handshake.
        let configured = unsafe {
            SSL_set_bridge_profile(
                ssl.as_ptr().cast(),
                order.as_ptr(),
                order.len(),
                i32::from(hello.extensions.contains(&21)),
            )
        };
        ensure!(configured == 1, "patched TLS profile rejected");
    }
    #[cfg(feature = "patched-tls")]
    {
        use foreign_types::ForeignType;
        unsafe extern "C" {
            fn SSL_set1_client_key_shares(
                ssl: *mut std::ffi::c_void,
                groups: *const u16,
                count: usize,
            ) -> std::ffi::c_int;
        }
        let shares: Vec<_> = hello
            .key_share_groups
            .iter()
            .copied()
            .filter(|id| group(*id).is_some())
            .collect();
        if !shares.is_empty() {
            // btls's KeyShare wrapper does not expose these new wire IDs.
            // The native API validates and copies them, and generates fresh keys.
            let ok = unsafe {
                SSL_set1_client_key_shares(ssl.as_ptr().cast(), shares.as_ptr(), shares.len())
            };
            ensure!(ok == 1, "patched TLS key shares rejected");
        }
    }
    #[cfg(not(feature = "patched-tls"))]
    {
        let shares: Vec<_> = hello
            .key_share_groups
            .iter()
            .filter_map(|id| share(*id))
            .collect();
        if !shares.is_empty() {
            ssl.set_client_key_shares(&shares)?;
        }
    }
    ssl.set_enable_ech_grease(hello.extensions.contains(&65037));
    // ALPS carries HTTP/2 settings outside HTTP frames. Do not invent settings;
    // omit and explicitly report until end-to-end ALPS translation is implemented.
    if hello.extensions.contains(&17513) || hello.extensions.contains(&17613) {
        limitations.push("ALPS not mirrored; compare extension diff".into());
    }
    if hello.extensions.contains(&41) || hello.extensions.contains(&42) {
        limitations.push("session resumption / 0-RTT not inherited".into());
    }
    Ok((ssl, limitations))
}

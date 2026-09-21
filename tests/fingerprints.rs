use fingerprint_bridge::{fingerprint::*, h1, h2, rewrite::Mapping};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn v16(bytes: &[u8]) -> Vec<u8> {
    let mut o = (bytes.len() as u16).to_be_bytes().to_vec();
    o.extend(bytes);
    o
}
fn ext(id: u16, b: &[u8]) -> Vec<u8> {
    let mut o = id.to_be_bytes().to_vec();
    o.extend(v16(b));
    o
}
fn hello(sni: &str, random: u8, g: u16) -> Vec<u8> {
    let mut b = vec![3, 3];
    b.extend([random; 32]);
    b.push(0);
    let mut c = g.to_be_bytes().to_vec();
    c.extend([0x13, 1, 0x13, 2, 0xc0, 0x2f]);
    b.extend(v16(&c));
    b.extend([1, 0]);
    let mut e = ext(g, &[]);
    let mut name = vec![0];
    name.extend(v16(sni.as_bytes()));
    e.extend(ext(0, &v16(&name)));
    e.extend(ext(10, &[0, 6, (g >> 8) as u8, g as u8, 0, 29, 0, 23]));
    e.extend(ext(11, &[1, 0]));
    e.extend(ext(13, &[0, 4, 4, 3, 8, 4]));
    e.extend(ext(
        16,
        &[
            0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ],
    ));
    e.extend(ext(43, &[4, 3, 4, 3, 3]));
    e.extend(ext(45, &[1, 1]));
    let mut share = vec![0, 29];
    share.extend(v16(&[random; 32]));
    e.extend(ext(51, &v16(&share)));
    b.extend(v16(&e));
    let mut hs = vec![1, 0, (b.len() >> 8) as u8, b.len() as u8];
    hs.extend(b);
    let mut record = vec![22, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
    record.extend(hs);
    record
}
#[test]
fn ja3_known_vector_and_natural_exemptions() {
    let a = client_hello(&hello("b.test", 1, 0x1a1a)).unwrap().unwrap();
    let b = client_hello(&hello("longer.a.test", 2, 0x2a2a))
        .unwrap()
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(
        a.ja3_string(),
        "771,4865-4866-49199,0-10-11-13-16-43-45-51,29-23,0"
    );
    assert_eq!(a.ja3(), "32cdfc1f48f0c16ef099a882fbd0ff36");
}
#[test]
fn tls_record_fragmentation_is_reassembled() {
    let r = hello("b.test", 1, 0x1a1a);
    let hs = &r[5..];
    let mut split = vec![];
    for b in hs.chunks(7) {
        split.extend([22, 3, 1, 0, b.len() as u8]);
        split.extend(b);
    }
    assert_eq!(client_hello(&split).unwrap(), client_hello(&r).unwrap());
    for end in 0..r.len() {
        assert!(client_hello(&r[..end]).unwrap().is_none());
    }
}
#[test]
fn tls_order_and_signature_changes_fail() {
    let a = client_hello(&hello("b.test", 1, 0x1a1a)).unwrap().unwrap();
    let mut b = a.clone();
    b.ciphers.swap(1, 2);
    assert_ne!(a.ja3(), b.ja3());
    assert!(!differences(&a.evidence(), &b.evidence()).is_empty());
    let mut b = a.clone();
    b.signature_algorithms.reverse();
    assert_eq!(a.ja3(), b.ja3());
    assert!(!differences(&a.evidence(), &b.evidence()).is_empty());
}
#[test]
fn truncated_and_invalid_tls_rejected() {
    assert!(client_hello(&[22, 3, 1, 255, 255]).is_err());
    assert!(client_hello(&[23, 3, 3, 0, 0]).is_err());
    assert!(client_hello(&vec![0; MAX_HELLO + 1]).is_err());
}
#[test]
fn grease_only_reserved_pattern() {
    assert!(grease(0xaaaa));
    assert!(grease(0xfafa));
    assert!(!grease(0x0a1a));
    assert!(!grease(0x1301));
}
#[test]
fn ja4_published_example_and_order_sensitivity() {
    let parse = |s: &str| {
        s.split(',')
            .map(|v| u16::from_str_radix(v, 16).unwrap())
            .collect::<Vec<_>>()
    };
    let mut h = client_hello(&hello("b.test", 1, 0x1a1a)).unwrap().unwrap();
    h.ciphers = parse("1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035");
    h.extensions =
        parse("001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015");
    h.signature_algorithms = parse("0403,0804,0401,0503,0805,0501,0806,0601");
    assert_eq!(h.ja4(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    let before = h.ja4();
    h.extensions.reverse();
    assert_eq!(before, h.ja4());
    h.signature_algorithms.reverse();
    assert_ne!(before, h.ja4());
}
#[test]
fn missing_evidence_is_not_a_pass() {
    let a = json!({"tls":{"ja3":"x"},"http":null});
    let r = compare(&a, &a, &["tls".into(), "http".into(), "tcp".into()]).unwrap();
    assert_eq!(r["pass"], false);
    assert_eq!(r["missing_layers"], json!(["http", "tcp"]));
    assert!(compare(&a, &a, &[]).is_err());
    assert_eq!(
        compare(&json!({"tcp":[]}), &json!({"tcp":[]}), &["tcp".into()]).unwrap()["pass"],
        false
    );
}
fn syn() -> Vec<u8> {
    let opts = vec![
        2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    let mut p = vec![0u8; 40 + opts.len()];
    p[0] = 0x45;
    let n = p.len() as u16;
    p[2..4].copy_from_slice(&n.to_be_bytes());
    p[6] = 0x40;
    p[8] = 64;
    p[9] = 6;
    p[32] = 0xa0;
    p[33] = 2;
    p[34..36].copy_from_slice(&64240u16.to_be_bytes());
    p[40..].copy_from_slice(&opts);
    p
}
#[test]
fn tcp_mss_window_scale_sack_order() {
    let s = tcp_syn(&syn()).unwrap().unwrap();
    assert_eq!(s.window, 64240);
    assert_eq!(
        s.options,
        vec![
            (2, "05b4".into()),
            (4, "".into()),
            (8, "present".into()),
            (1, "".into()),
            (3, "07".into())
        ]
    );
}
#[test]
fn tcp_random_sequence_timestamps_ports_ignored() {
    let a = syn();
    let mut b = a.clone();
    b[20..32].fill(17);
    b[48..56].fill(99);
    assert_eq!(tcp_syn(&a).unwrap(), tcp_syn(&b).unwrap());
}
#[test]
fn tcp_stable_changes_detected() {
    let a = syn();
    for index in [8, 34, 43, 59] {
        let mut b = a.clone();
        b[index] ^= 1;
        assert_ne!(tcp_syn(&a).unwrap(), tcp_syn(&b).unwrap());
    }
}
#[test]
fn tcp_malformed_options_and_fragments_rejected() {
    let mut s = syn();
    s[41] = 0;
    assert!(tcp_syn(&s).is_err());
    let mut s = syn();
    s[6] |= 0x20;
    assert!(tcp_syn(&s).is_err());
    assert!(tcp_syn(&[]).is_err());
}
#[test]
fn classic_pcap_extracts_real_packet_structure() {
    let mut p = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    p.extend([0; 12]);
    p.extend(101u32.to_le_bytes());
    let ip = syn();
    p.extend([0; 8]);
    p.extend((ip.len() as u32).to_le_bytes());
    p.extend((ip.len() as u32).to_le_bytes());
    p.extend(ip);
    assert_eq!(pcap_syns(&p).unwrap().len(), 1);
    p.pop();
    assert!(pcap_syns(&p).is_err());
}
fn map() -> Mapping {
    Mapping::new("b.test:8443", "a.test:9443").unwrap()
}
#[test]
fn request_preserves_casing_order_cookie_whitespace_body_boundary() {
    let input=b"POST /a%2Fb?q=x HTTP/1.1\r\nhOsT:\tb.test:8443 \r\nX-Z: 1\r\nCookie: sid=from_B; z=2\r\nX-A: 2\r\nContent-Length: 0\r\n\r\n";
    let output = map().h1_head(input, false).unwrap();
    let expected=b"POST /a%2Fb?q=x HTTP/1.1\r\nhOsT:\ta.test:9443 \r\nX-Z: 1\r\nCookie: sid=from_B; z=2\r\nX-A: 2\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(output, expected);
}
#[test]
fn cookie_domain_only_and_host_only_untouched() {
    let m = map();
    for (a, b) in [
        (
            "sid=Domain=a.test; Domain=.a.test; Path=/; Secure; HttpOnly; SameSite=Lax",
            "sid=Domain=a.test; Domain=.b.test; Path=/; Secure; HttpOnly; SameSite=Lax",
        ),
        ("id=1; domain= a.test ", "id=1; domain= b.test "),
        ("__Host-id=1; Path=/; Secure", "__Host-id=1; Path=/; Secure"),
        ("id=1; Domain=other.test", "id=1; Domain=other.test"),
    ] {
        assert_eq!(
            m.value(b"Set-Cookie", a.as_bytes(), true).unwrap(),
            b.as_bytes()
        );
    }
}
#[test]
fn url_rewrite_exact_authority_preserves_path_and_query() {
    let m = map();
    assert_eq!(
        m.value(
            b"Referer",
            b"https://b.test:8443/a%2Fb?q=b.test:8443",
            false
        )
        .unwrap(),
        b"https://a.test:9443/a%2Fb?q=b.test:8443"
    );
    assert_eq!(
        m.value(b"Location", b"//a.test:9443/x", true).unwrap(),
        b"//b.test:8443/x"
    );
    assert_eq!(
        m.value(b"Origin", b"https://b.test.attacker.test:8443", false)
            .unwrap(),
        b"https://b.test.attacker.test:8443"
    );
}
#[test]
fn host_injection_duplicates_and_foreign_authority_rejected() {
    for h in [
        b"GET / HTTP/1.1\r\nHost: other.test\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost: b.test:8443\r\nHost: b.test:8443\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: b.test:8443\r\n folded: value\r\n\r\n",
    ] {
        assert!(map().h1_head(h, false).is_err());
    }
    assert!(Mapping::new("b.test\r\nX: injected", "a.test").is_err());
}
#[test]
fn ambiguous_framing_is_rejected() {
    for h in [
        b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
    ] {
        assert!(h1::framing(h, false, false).is_err());
    }
}
#[test]
fn hpack_dynamic_state_is_kept_between_requests() {
    let m = map();
    let mut encoder = hpack::Encoder::new();
    let mut decoder = hpack::Decoder::new();
    let mut out = hpack::Decoder::new();
    let headers = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":authority".to_vec(), b"b.test:8443".to_vec()),
        (b"cookie".to_vec(), b"id=from_B".to_vec()),
        (b"x-repeat".to_vec(), b"yes".to_vec()),
    ];
    for _ in 0..3 {
        let block = encoder.encode(headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        let rewritten = h2::rewrite_block(&mut decoder, &block, &m, false, 4096).unwrap();
        let got = out.decode(&rewritten).unwrap();
        let mut expected = headers.clone();
        expected[1].1 = b"a.test:9443".to_vec();
        assert_eq!(got, expected);
    }
}
#[test]
fn hpack_rfc7541_huffman_vector_decodes() {
    let block = hex::decode("828684418cf1e3c2e5f23a6ba0ab90f4ff").unwrap();
    let m = Mapping::new("www.example.com", "upstream.example.com").unwrap();
    let output = h2::rewrite_block(&mut hpack::Decoder::new(), &block, &m, false, 4096).unwrap();
    let headers = hpack::Decoder::new().decode(&output).unwrap();
    assert_eq!(
        headers[3],
        (b":authority".to_vec(), b"upstream.example.com".to_vec())
    );
}
#[test]
fn hpack_excessive_table_update_rejected() {
    let block = [0x3f, 0xe2, 0x1f];
    assert!(h2::rewrite_block(&mut hpack::Decoder::new(), &block, &map(), false, 4096).is_err());
}
#[test]
fn h2_settings_priority_padding_and_order() {
    let frame = h2::Frame {
        kind: 4,
        flags: 0,
        stream: 0,
        payload: vec![0, 4, 0, 96, 0, 0, 0, 1, 0, 1, 0, 0],
    };
    assert_eq!(
        h2::settings(&frame).unwrap(),
        vec![(4, 6291456), (1, 65536)]
    );
    let f = h2::Frame {
        kind: 1,
        flags: 0x29,
        stream: 7,
        payload: vec![2, 0, 0, 0, 0, 255, 1, 2, 9, 9],
    };
    let frames = h2::reframe(&f, &vec![42; 18000]).unwrap();
    assert_eq!(frames[0].stream, 7);
    assert_eq!(frames[0].flags, 0x29);
    assert_eq!(&frames[0].payload[..6], &f.payload[..6]);
    assert_eq!(&frames[0].payload[frames[0].payload.len() - 2..], &[9, 9]);
    assert_eq!(frames[1].kind, 9);
    assert_eq!(frames[1].flags, 4);
}

#[tokio::test]
async fn h1_continue_chunked_keepalive_end_to_end() {
    let (mut browser, client) = tokio::io::duplex(65536);
    let (upstream, mut origin) = tokio::io::duplex(65536);
    let task = tokio::spawn(h1::bridge(client, upstream, map()));
    let server = tokio::spawn(async move {
        let mut r = tokio::io::BufReader::new(&mut origin);
        let h = h1::head(&mut r).await.unwrap();
        assert!(String::from_utf8_lossy(&h).contains("Host: a.test:9443"));
        r.get_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();
        let mut body = vec![];
        h1::body(&mut r, &mut body, h1::Body::Chunked)
            .await
            .unwrap();
        assert_eq!(body, b"3;ext=yes\r\nabc\r\n0\r\nX-T: v\r\n\r\n");
        r.get_mut().write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: id=1; Domain=a.test; HttpOnly\r\nContent-Length: 2\r\n\r\nOK").await.unwrap();
        let h = h1::head(&mut r).await.unwrap();
        assert!(h.starts_with(b"HEAD /"));
        r.get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n")
            .await
            .unwrap();
    });
    browser.write_all(b"POST / HTTP/1.1\r\nHost: b.test:8443\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n").await.unwrap();
    let mut r = tokio::io::BufReader::new(browser);
    assert!(h1::head(&mut r).await.unwrap().starts_with(b"HTTP/1.1 100"));
    r.get_mut()
        .write_all(b"3;ext=yes\r\nabc\r\n0\r\nX-T: v\r\n\r\n")
        .await
        .unwrap();
    let h = h1::head(&mut r).await.unwrap();
    assert!(String::from_utf8_lossy(&h).contains("Domain=b.test"));
    let mut body = [0; 2];
    r.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"OK");
    r.get_mut()
        .write_all(b"HEAD / HTTP/1.1\r\nHost: b.test:8443\r\n\r\n")
        .await
        .unwrap();
    assert!(h1::head(&mut r).await.unwrap().starts_with(b"HTTP/1.1 200"));
    r.get_mut().shutdown().await.unwrap();
    server.await.unwrap();
    task.await.unwrap().unwrap();
}

proptest::proptest! {
    #[test]fn wire_parsers_do_not_panic(b in proptest::collection::vec(proptest::num::u8::ANY,0..2048)) {let _=client_hello(&b);let _=tcp_syn(&b);let _=pcap_syns(&b);}
}

async fn emitted_hello(ssl: btls::ssl::Ssl) -> TlsHello {
    let (wire, mut peer) = tokio::io::duplex(65536);
    let mut stream = tokio_btls::SslStream::new(ssl, wire).unwrap();
    let client = tokio::spawn(async move {
        let _ = std::pin::Pin::new(&mut stream).connect().await;
    });
    let parsed = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut b = vec![];
        loop {
            let mut chunk = [0; 4096];
            let n = peer.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            b.extend(&chunk[..n]);
            if let Some(h) = client_hello(&b).unwrap() {
                break h;
            }
        }
    })
    .await
    .unwrap();
    drop(peer);
    client.await.unwrap();
    parsed
}

#[tokio::test]
async fn native_tls_mirror_preserves_supported_client_profile() {
    use btls::ssl::{SslConnector, SslMethod, SslSignatureAlgorithm, SslVersion};
    let mut c = SslConnector::builder(SslMethod::tls()).unwrap();
    c.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    c.set_preserve_tls13_cipher_list(true);
    c.set_strict_cipher_list("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256").unwrap();
    c.set_curves_list("X25519:P-256").unwrap();
    c.set_verify_algorithm_prefs(&[
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA256,
    ])
    .unwrap();
    c.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
    c.enable_ocsp_stapling();
    c.enable_signed_cert_timestamps();
    let incoming = emitted_hello(c.build().configure().unwrap().into_ssl("b.test").unwrap()).await;
    let (ssl, limitations) = fingerprint_bridge::tls::mirror(&incoming, "a.test", None).unwrap();
    assert!(limitations.is_empty(), "{limitations:?}");
    let outgoing = emitted_hello(ssl).await;
    assert_eq!(
        incoming,
        outgoing,
        "{:?}",
        differences(&incoming.evidence(), &outgoing.evidence())
    );
}

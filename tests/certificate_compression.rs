//! Independent C Zstandard encoder against B's pure Rust decoder, over real TLS.
use btls::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslAcceptor, SslConnector, SslFiletype,
    SslMethod, SslVersion,
};
use std::{
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Valid,
    BadFrame,
    BadSignature,
}
struct Encoder {
    mode: Mode,
    used: Arc<AtomicBool>,
}
impl CertificateCompressor for Encoder {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZSTD;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;
    fn compress<W: Write>(&self, input: &[u8], out: &mut W) -> io::Result<()> {
        self.used.store(true, Ordering::SeqCst);
        let mut certificate = input.to_vec();
        if self.mode == Mode::BadSignature {
            // TLS 1.3 Certificate: context<0..255>, list<0..2^24-1>, DER<1..2^24-1>.
            let p = 1 + usize::from(certificate[0]) + 3;
            let n = (usize::from(certificate[p]) << 16)
                | (usize::from(certificate[p + 1]) << 8)
                | usize::from(certificate[p + 2]);
            certificate[p + 3 + n - 1] ^= 1; // last octet of leaf signature, not its public key
        }
        let mut compressed = zstd::stream::encode_all(certificate.as_slice(), 3)?;
        if self.mode == Mode::BadFrame {
            compressed[0] ^= 0xff;
        }
        out.write_all(&compressed)
    }
    fn decompress<W: Write>(&self, input: &[u8], out: &mut W) -> io::Result<()> {
        zstd::stream::copy_decode(input, out)
    }
}
struct Lab(PathBuf);
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Bridge(Child);
impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn openssl(path: &Path, args: &[&str]) {
    assert!(Command::new("openssl")
        .current_dir(path)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
}
fn certificates(path: &Path) {
    openssl(
        path,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=Compression Lab CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            "root.key",
            "-out",
            "root.pem",
        ],
    );
    openssl(
        path,
        &[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=a.test",
            "-keyout",
            "leaf.key",
            "-out",
            "leaf.csr",
        ],
    );
    fs::write(path.join("leaf.ext"), "subjectAltName=DNS:a.test,DNS:b.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n").unwrap();
    openssl(
        path,
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            "leaf.ext",
            "-out",
            "leaf.pem",
        ],
    );
}
#[test]
fn zstd_certificate_real_http_and_corruption_rejection() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let lab = Lab(Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("bridge-zstd-{}-{stamp}", std::process::id())));
    fs::create_dir(&lab.0).unwrap();
    certificates(&lab.0);
    for mode in [Mode::Valid, Mode::BadFrame, Mode::BadSignature] {
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        origin.set_nonblocking(true).unwrap();
        let address = origin.local_addr().unwrap();
        let used = Arc::new(AtomicBool::new(false));
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        acceptor
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        acceptor
            .set_certificate_file(lab.0.join("leaf.pem"), SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_private_key_file(lab.0.join("leaf.key"), SslFiletype::PEM)
            .unwrap();
        acceptor
            .add_certificate_compression_algorithm(Encoder {
                mode,
                used: used.clone(),
            })
            .unwrap();
        let acceptor = acceptor.build();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let raw = loop {
                match origin.accept() {
                    Ok((raw, _)) => break raw,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("origin accept: {e}"),
                }
            };
            raw.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            raw.set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut tls = match acceptor.accept(raw) {
                Ok(tls) => tls,
                Err(e) => {
                    eprintln!("origin handshake ({mode:?}): {e}");
                    return false;
                }
            };
            let mut request = Vec::new();
            let mut byte = [0];
            while request.len() < 65536 && !request.ends_with(b"\r\n\r\n") {
                if tls.read_exact(&mut byte).is_err() {
                    return false;
                }
                request.push(byte[0]);
            }
            assert!(String::from_utf8_lossy(&request)
                .contains(&format!("Host: a.test:{}\r\n", address.port())));
            assert!(String::from_utf8_lossy(&request).contains("Cookie: sid=from_B\r\n"));
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            let _ = tls.shutdown();
            true
        });
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = reserved.local_addr().unwrap();
        drop(reserved);
        let reports = lab.0.join(format!("{mode:?}"));
        let log_path = lab.0.join(format!("{mode:?}.log"));
        let mut bridge = Bridge(
            Command::new(env!("CARGO_BIN_EXE_fingerprint-bridge"))
                .args([
                    "serve",
                    "--listen",
                    &listen.to_string(),
                    "--public",
                    &format!("b.test:{}", listen.port()),
                    "--upstream",
                    &format!("a.test:{}", address.port()),
                    "--connect",
                    &address.to_string(),
                ])
                .arg("--cert")
                .arg(lab.0.join("leaf.pem"))
                .arg("--key")
                .arg(lab.0.join("leaf.key"))
                .arg("--ca")
                .arg(lab.0.join("root.pem"))
                .arg("--reports")
                .arg(&reports)
                .stdout(Stdio::null())
                .stderr(fs::File::create(&log_path).unwrap())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if TcpStream::connect(listen).is_ok() {
                break;
            }
            assert!(bridge.0.try_wait().unwrap().is_none(), "B exited");
            assert!(Instant::now() < deadline, "B not ready");
            thread::sleep(Duration::from_millis(10));
        }
        let mut client = SslConnector::builder(SslMethod::tls()).unwrap();
        client.set_ca_file(lab.0.join("root.pem")).unwrap();
        client
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        client
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        client
            .add_certificate_compression_algorithm(Encoder {
                mode: Mode::Valid,
                used: Arc::new(AtomicBool::new(false)),
            })
            .unwrap();
        let raw = TcpStream::connect(listen).unwrap();
        raw.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        raw.set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut response = Vec::new();
        if let Ok(mut tls) = client.build().connect("b.test", raw) {
            let request = format!("GET /compression HTTP/1.1\r\nHost: b.test:{}\r\nCookie: sid=from_B\r\nConnection: close\r\n\r\n",listen.port());
            let _ = tls.write_all(request.as_bytes());
            // Read the declared HTTP response rather than waiting for TLS EOF.
            let mut byte = [0];
            while response.len() < 65536 && !response.ends_with(b"\r\n\r\n") {
                if tls.read_exact(&mut byte).is_err() {
                    break;
                }
                response.push(byte[0]);
            }
            let mut body = [0; 2];
            if tls.read_exact(&mut body).is_ok() {
                response.extend(body);
            }
        }
        let received_http = server.join().unwrap();
        assert!(
            used.load(Ordering::SeqCst),
            "{mode:?}: certificate compression never negotiated"
        );
        assert_eq!(received_http, mode == Mode::Valid, "{mode:?}");
        assert_eq!(
            response.starts_with(b"HTTP/1.1 200 OK\r\n"),
            mode == Mode::Valid,
            "{mode:?}"
        );
        if mode == Mode::Valid {
            assert!(response.ends_with(b"\r\n\r\nok"));
        } else {
            let expected = if mode == Mode::BadFrame {
                "CERT_DECOMPRESSION_FAILED"
            } else {
                "CERTIFICATE_VERIFY_FAILED"
            };
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let log = fs::read_to_string(&log_path).unwrap();
                if log.contains(expected) {
                    break;
                }
                assert!(Instant::now() < deadline, "{mode:?}: {log}");
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

//! Independent reqwest/rustls client; never uses the bridge's TLS implementation.
use anyhow::{ensure, Result};
use reqwest::{blocking::Client, Certificate, Version};
use std::{env, fs, net::SocketAddr, time::Duration};

fn main() -> Result<()> {
    let a: Vec<String> = env::args().collect();
    ensure!(
        a.len() == 6,
        "usage: language-client CA HOSTS PROTOCOL A_PORT B_PORT"
    );
    let ca = Certificate::from_pem(&fs::read(&a[1])?)?;
    for (host, port) in [("a.test", &a[4]), ("a.test", &a[4]), ("b.test", &a[5])] {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(ca.clone())
            .resolve(host, addr)
            .timeout(Duration::from_secs(15));
        builder = if a[3] == "h2" {
            builder.http2_prior_knowledge()
        } else {
            builder.http1_only()
        };
        let client = builder.build()?;
        let base = format!("https://{host}:{port}");
        for n in [1, 2] {
            let response = client
                .get(format!("{base}/fingerprint/{n}?encoded=%2F"))
                .header("User-Agent", "fp-matrix/rust")
                .header("Cookie", "sid=from_B; flag=yes")
                .header("Origin", &base)
                .header("Referer", format!("{base}/home"))
                .header("X-Order-Z", "z")
                .header("X-Order-A", "a")
                .send()?;
            ensure!(response.status() == 200, "status");
            ensure!(
                response.version()
                    == if a[3] == "h2" {
                        Version::HTTP_2
                    } else {
                        Version::HTTP_11
                    },
                "protocol downgrade"
            );
            ensure!(
                response.headers()["set-cookie"]
                    .to_str()?
                    .contains(&format!("Domain={host}")),
                "cookie domain"
            );
            ensure!(
                response.headers()["location"].to_str()? == format!("{base}/next"),
                "location"
            );
            ensure!(response.bytes()?.as_ref() == b"FP_OK", "response body");
        }
    }
    println!("rust reqwest/rustls: three connections completed");
    Ok(())
}

use anyhow::{ensure, Context, Result};
use btls::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, SslVersion},
    x509::X509,
};
use clap::{Parser, Subcommand};
use fingerprint_bridge::{fingerprint, h1, h2, rewrite::Mapping, tls, transport};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpListener};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Terminate HTTPS for B and bridge to one fixed, verified HTTPS origin A.
    Serve(Serve),
    /// Extract normalized TLS features and JA3 from binary TLS records.
    InspectHello { input: PathBuf },
    /// Extract initial TCP SYN features from classic pcap (filter flows beforehand).
    InspectPcap { input: PathBuf },
    /// Fail on any difference or missing required layer. Exit 0=match, 1=diff, 2=error.
    Compare {
        baseline: PathBuf,
        observed: PathBuf,
        #[arg(long, value_delimiter = ',', default_value = "tls,http,tcp")]
        layers: Vec<String>,
    },
}
#[derive(Parser, Clone)]
struct Serve {
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// B's public authority, e.g. b.example:8443.
    #[arg(long)]
    public: String,
    /// A's authority, e.g. a.example:443. Requests cannot choose another origin.
    #[arg(long)]
    upstream: String,
    #[arg(long)]
    cert: PathBuf,
    #[arg(long)]
    key: PathBuf,
    /// Additional trusted root CA, used for lab/private origins. Verification stays on.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Optional fixed upstream socket; SNI and verification still use --upstream.
    #[arg(long)]
    connect: Option<SocketAddr>,
    /// Save per-connection TLS evidence, with missing HTTP/TCP layers marked null.
    #[arg(long)]
    reports: Option<PathBuf>,
    /// Diagnostic plaintext request capture (includes cookies); requires --reports.
    #[arg(long, requires = "reports")]
    http_evidence: bool,
    /// Reject before forwarding HTTP if measured normalized TLS features differ.
    #[arg(long)]
    strict_tls: bool,
    #[arg(long, default_value_t = 256)]
    max_connections: usize,
    #[arg(long, default_value_t = 15)]
    handshake_timeout: u64,
    /// Hard connection lifetime, not an idle timeout.
    #[arg(long, default_value_t = 3600)]
    connection_lifetime: u64,
    /// Optional Linux TCP_MAXSEG before connect; not a complete TCP fingerprint clone.
    #[arg(long)]
    tcp_mss: Option<u32>,
    #[arg(long)]
    ttl: Option<u32>,
}
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let result = run(Cli::parse()).await;
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(2)
        }
    }
}
async fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::InspectHello { input } => {
            let b = std::fs::read(input)?;
            let h = fingerprint::client_hello(&b)?.context("incomplete ClientHello")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"tls":h.evidence()}))?
            );
            Ok(0)
        }
        Command::InspectPcap { input } => {
            let b = std::fs::read(input)?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"tcp":fingerprint::pcap_syns(&b)?})
                )?
            );
            Ok(0)
        }
        Command::Compare {
            baseline,
            observed,
            layers,
        } => {
            let result = fingerprint::compare(
                &fingerprint::load_json(&baseline)?,
                &fingerprint::load_json(&observed)?,
                &layers,
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(if result["pass"] == true { 0 } else { 1 })
        }
        Command::Serve(config) => {
            serve(config).await?;
            Ok(0)
        }
    }
}
async fn serve(config: Serve) -> Result<()> {
    ensure!(
        config.max_connections > 0
            && config.handshake_timeout > 0
            && config.connection_lifetime > 0,
        "limits must be positive"
    );
    let mapping = Mapping::new(&config.public, &config.upstream)?;
    let certs = X509::stack_from_pem(&std::fs::read(&config.cert)?)?;
    ensure!(!certs.is_empty(), "empty certificate chain");
    let key = PKey::private_key_from_pem(&std::fs::read(&config.key)?)?;
    let mut check = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    check.set_certificate(&certs[0])?;
    check.set_private_key(&key)?;
    check.check_private_key()?;
    if let Some(path) = &config.reports {
        tokio::fs::create_dir_all(path).await?;
    }
    let listener = TcpListener::bind(config.listen).await?;
    tracing::info!(listen=%listener.local_addr()?,"bridge ready; TCP and full browser equivalence are not certified");
    let limit = Arc::new(tokio::sync::Semaphore::new(config.max_connections));
    let mut tasks = tokio::task::JoinSet::new();
    let mut count = 0u64;
    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    loop {
        tokio::select! {
            accept=listener.accept()=>{let (stream,_)=accept?;let Ok(permit)=limit.clone().try_acquire_owned()else{tracing::warn!("connection limit reached");continue};
                count+=1;let id=format!("{run_id}-{count}");let cfg=config.clone();let m=mapping.clone();let chain=certs.clone();let key=key.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, cfg, m, chain, key, id).await;
                });
            }
            Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if let Err(e)=result{tracing::error!(error=%e,"connection task failed")}}
            _=tokio::signal::ctrl_c()=>break,
        }
    }
    drop(listener);
    if tokio::time::timeout(Duration::from_secs(10), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
    }
    Ok(())
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    cfg: Serve,
    m: Mapping,
    chain: Vec<X509>,
    key: PKey<btls::pkey::Private>,
    id: String,
) {
    let result=tokio::time::timeout(Duration::from_secs(cfg.connection_lifetime),async{
                    let setup=async{
                        let mut raw=stream;let (prefix,hello)=transport::read_hello(&mut raw).await?;
                        let (ssl,limitations)=tls::mirror(&hello,m.upstream_host.trim_matches(['[',']']),cfg.ca.as_deref())?;
                        let addr=if let Some(addr)=cfg.connect{addr}else{tokio::net::lookup_host((m.upstream_host.trim_matches(['[',']']),m.upstream_port)).await?.next().context("no upstream address")?};
                        let tcp=transport::connect(addr,cfg.tcp_mss,cfg.ttl).await?;
                        let capture=Arc::new(Mutex::new(transport::Capture::default()));
                        let mut upstream=tokio_btls::SslStream::new(ssl,transport::Tap{inner:tcp,capture:capture.clone()})?;std::pin::Pin::new(&mut upstream).connect().await?;
                        let outgoing=fingerprint::client_hello(&capture.lock().unwrap().bytes)?.context("outbound ClientHello not captured")?;
                        let a=serde_json::json!({"tls":hello.evidence(),"http":null,"tcp":null});let b=serde_json::json!({"tls":outgoing.evidence(),"http":null,"tcp":null});
                        let comparison=fingerprint::compare(&a,&b,&["tls".into()])?;
                        if let Some(path)=&cfg.reports{
                            for (suffix,value) in [("inbound",&a),("outbound",&b)]{
                                let mut f=tokio::fs::OpenOptions::new().write(true).create_new(true).open(path.join(format!("{id}.{suffix}.json"))).await?;f.write_all(&serde_json::to_vec_pretty(value)?).await?;
                            }
                            let report=serde_json::json!({"comparison":comparison,"limitations":limitations,"scope":"B inbound vs B outbound, not independent direct-to-A baseline","unverified":["http","tcp"]});
                            tokio::fs::write(path.join(format!("{id}.report.json")),serde_json::to_vec_pretty(&report)?).await?;
                        }
                        tracing::info!(connection=%id,tls_match=comparison["pass"]==true,differences=comparison["differences"].as_array().map_or(0,|v|v.len()),limitations=?limitations,"TLS comparison");
                        ensure!(!cfg.strict_tls||comparison["pass"]==true,"strict TLS comparison failed; no HTTP forwarded");
                        let selected=upstream.ssl().selected_alpn_protocol().unwrap_or(b"http/1.1").to_vec();ensure!(selected==b"h2"||selected==b"http/1.1","unsupported upstream ALPN");
                        let mut accept=SslAcceptor::mozilla_intermediate(SslMethod::tls())?;accept.set_min_proto_version(Some(SslVersion::TLS1_2))?;accept.set_certificate(&chain[0])?;
                        for c in chain.iter().skip(1){accept.add_extra_chain_cert(c.clone())?;}accept.set_private_key(&key)?;accept.check_private_key()?;
                        let chosen=selected.clone();accept.set_alpn_select_callback(move|_,offers|{let mut p=0;while p<offers.len(){let n=offers[p] as usize;p+=1;if p+n>offers.len(){return Err(AlpnError::ALERT_FATAL)}
if offers[p..p+n]==chosen{return Ok(&offers[p..p+n])}p+=n;}Err(AlpnError::NOACK)});
                        let mut client=tokio_btls::SslStream::new(Ssl::new(accept.build().context())?,transport::Replay::new(raw,prefix))?;std::pin::Pin::new(&mut client).accept().await?;
                        Ok::<_,anyhow::Error>((client,upstream,selected))
                    };
                    let (client,upstream,selected)=tokio::time::timeout(Duration::from_secs(cfg.handshake_timeout),setup).await.context("handshake timeout")??;
                    if cfg.http_evidence {
                        let incoming=Arc::new(Mutex::new(transport::HttpCapture::default()));
                        let outgoing=Arc::new(Mutex::new(transport::HttpCapture::default()));
                        let client=transport::HttpTap{inner:client,capture:incoming.clone(),on_read:true};
                        let upstream=transport::HttpTap{inner:upstream,capture:outgoing.clone(),on_read:false};
                        let result=if selected==b"h2"{h2::bridge(client,upstream,m).await}else{h1::bridge(client,upstream,m).await};
                        let evidence=serde_json::json!({"protocol":String::from_utf8_lossy(&selected),"inbound":*incoming.lock().unwrap(),"outbound":*outgoing.lock().unwrap()});
                        let path=cfg.reports.as_ref().context("reports required")?.join(format!("{id}.http.json"));
                        transport::write_private_evidence(&path,&serde_json::to_vec(&evidence)?).await?;
                        result
                    }else if selected==b"h2"{h2::bridge(client,upstream,m).await}else{h1::bridge(client,upstream,m).await}
                }).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(connection=%id,error=%e,"connection ended with error"),
        Err(_) => tracing::warn!(connection=%id,"connection lifetime exceeded"),
    }
}

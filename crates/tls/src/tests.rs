use std::io::{Read, Write};
use std::string::{String, ToString};
use std::sync::Arc;
use std::vec;
use std::vec::Vec;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;

use super::*;

static RNG: osmium_rand::SharedRng = osmium_rand::SharedRng::new();

fn rng() -> &'static osmium_rand::SharedRng {
    if !RNG.is_seeded() {
        RNG.seed(&osmium_rand::CpuEntropy).expect("host entropy");
    }
    &RNG
}

/// 2027-01-15, inside every certificate the tests make.
const NOW: u64 = 1_800_000_000;

#[derive(Debug)]
struct FixedTime(u64);

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(self.0)))
    }
}

struct Server {
    config: Arc<rustls::ServerConfig>,
    cert: CertificateDer<'static>,
}

fn server(now: u64) -> Server {
    let names = [cert::SubjectName::Dns("hyperon.test"), cert::SubjectName::Ip([127, 0, 0, 1].into())];
    let validity = cert::Validity { not_before: now - 86_400, not_after: now + 365 * 86_400 };
    let id = cert::self_signed(rng(), &names, validity).expect("certificate");
    let cert = CertificateDer::from(id.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_pkcs8_der.clone()));
    let config =
        server_config(shared_provider(rng()), Arc::new(FixedTime(now)), vec![cert.clone()], key).expect("config");
    Server { config, cert }
}

fn client(cert: &CertificateDer<'static>, name: &str) -> rustls::ClientConnection {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("root");
    let config = rustls::ClientConfig::builder_with_details(shared_provider(rng()), Arc::new(FixedTime(NOW)))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    rustls::ClientConnection::new(Arc::new(config), ServerName::try_from(String::from(name)).expect("name"))
        .expect("client")
}

/// Moves bytes both ways until neither side has anything to send.
fn pump(c: &mut rustls::ClientConnection, s: &mut ServerSession) -> Result<(), Error> {
    pump_into(c, s, None)
}

/// [`pump`], also moving the client's decrypted data into `sink` as it
/// arrives, so its receive buffer never fills.
fn pump_into(
    c: &mut rustls::ClientConnection,
    s: &mut ServerSession,
    mut sink: Option<&mut Vec<u8>>,
) -> Result<(), Error> {
    for _ in 0..1000 {
        let mut moved = false;
        while c.wants_write() {
            let mut buf = Vec::new();
            c.write_tls(&mut buf).expect("client write_tls");
            let mut rest = &buf[..];
            while !rest.is_empty() {
                let n = s.receive(rest)?;
                rest = &rest[n..];
                if n == 0 {
                    drain_server(s);
                }
            }
            moved = true;
        }
        if !s.outgoing().is_empty() {
            let out = s.outgoing().to_vec();
            s.sent(out.len());
            let mut rest = &out[..];
            while !rest.is_empty() {
                c.read_tls(&mut rest).expect("client read_tls");
                c.process_new_packets().map_err(|e| Error::General(std::format!("client: {e}")))?;
                if let Some(sink) = sink.as_deref_mut() {
                    sink.extend(client_read(c));
                }
            }
            moved = true;
        }
        if !moved {
            return Ok(());
        }
    }
    panic!("pump never settled");
}

fn drain_server(s: &mut ServerSession) -> Vec<u8> {
    let mut out = vec![0u8; s.readable()];
    let n = s.read(&mut out);
    out.truncate(n);
    out
}

fn client_read(c: &mut rustls::ClientConnection) -> Vec<u8> {
    let mut out = Vec::new();
    match c.reader().read_to_end(&mut out) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => panic!("client read: {e}"),
    }
    out
}

#[test]
fn handshake_then_echo_then_close() {
    let srv = server(NOW);
    let mut s = ServerSession::new(srv.config.clone()).expect("session");
    let mut c = client(&srv.cert, "hyperon.test");
    assert!(s.is_handshaking());
    pump(&mut c, &mut s).expect("handshake");
    assert!(!s.is_handshaking());
    assert_eq!(
        c.negotiated_cipher_suite().map(|cs| cs.suite()),
        Some(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
    );
    assert_eq!(c.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));

    c.writer().write_all(b"ping").expect("client write");
    pump(&mut c, &mut s).expect("ping");
    assert_eq!(drain_server(&mut s), b"ping");
    s.write(b"pong").expect("server write");
    pump(&mut c, &mut s).expect("pong");
    assert_eq!(client_read(&mut c), b"pong");

    c.send_close_notify();
    pump(&mut c, &mut s).expect("close");
    assert!(s.peer_closed());
    assert!(s.write(b"late").is_err());
}

#[test]
fn data_written_during_the_handshake_is_held_until_it_finishes() {
    let srv = server(NOW);
    let mut s = ServerSession::new(srv.config.clone()).expect("session");
    let mut c = client(&srv.cert, "hyperon.test");
    s.write(b"early").expect("queue");
    assert!(s.outgoing().is_empty(), "nothing goes out before the client hello");
    pump(&mut c, &mut s).expect("handshake");
    assert_eq!(client_read(&mut c), b"early");
}

#[test]
fn large_transfers_both_ways() {
    let srv = server(NOW);
    let mut s = ServerSession::new(srv.config.clone()).expect("session");
    let mut c = client(&srv.cert, "hyperon.test");
    pump(&mut c, &mut s).expect("handshake");
    let up: Vec<u8> = (0..200_000u32).map(|i| (i * 31 % 251) as u8).collect();
    let mut got = Vec::new();
    // The rustls client buffers at most 64 KiB of plaintext, so feed it in pieces.
    for chunk in up.chunks(10_000) {
        c.writer().write_all(chunk).expect("client write");
        pump(&mut c, &mut s).expect("upload");
        got.extend(drain_server(&mut s));
    }
    assert_eq!(got, up);

    let down: Vec<u8> = up.iter().rev().copied().collect();
    s.write(&down).expect("server write");
    let mut got = Vec::new();
    pump_into(&mut c, &mut s, Some(&mut got)).expect("download");
    assert_eq!(got, down);
}

#[test]
fn client_refuses_a_certificate_for_another_name() {
    let srv = server(NOW);
    let mut s = ServerSession::new(srv.config.clone()).expect("session");
    let mut c = client(&srv.cert, "other.test");
    let err = pump(&mut c, &mut s).expect_err("must fail");
    assert!(std::format!("{err}").contains("certificate"), "{err}");
}

#[test]
fn client_accepts_the_ip_address_name() {
    let srv = server(NOW);
    let mut s = ServerSession::new(srv.config.clone()).expect("session");
    let mut c = client(&srv.cert, "127.0.0.1");
    pump(&mut c, &mut s).expect("handshake by IP");
}

#[test]
fn tampered_record_is_rejected() {
    let srv = server(NOW);
    let mut s = ServerSession::new(srv.config.clone()).expect("session");
    let mut c = client(&srv.cert, "hyperon.test");
    pump(&mut c, &mut s).expect("handshake");
    c.writer().write_all(b"secret").expect("client write");
    let mut record = Vec::new();
    c.write_tls(&mut record).expect("write_tls");
    let last = record.len() - 1;
    record[last] ^= 1;
    assert!(s.receive(&record).is_err());
    assert!(s.is_closed());
    // The alert telling the client why is still there to send.
    assert!(!s.outgoing().is_empty());
}

#[test]
fn garbage_is_rejected_without_panicking() {
    let srv = server(NOW);
    let mut s = ServerSession::new(srv.config.clone()).expect("session");
    assert!(s.receive(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_err());
    assert!(s.is_closed());
}

#[test]
fn certificate_needs_names_and_a_sane_validity() {
    let v = cert::Validity { not_before: NOW, not_after: NOW + 1 };
    assert_eq!(cert::self_signed(rng(), &[], v).err(), Some(cert::CertError::NoNames));
    assert_eq!(cert::self_signed(rng(), &[cert::SubjectName::Dns("")], v).err(), Some(cert::CertError::InvalidName));
    let backwards = cert::Validity { not_before: NOW, not_after: NOW - 1 };
    assert_eq!(
        cert::self_signed(rng(), &[cert::SubjectName::Dns("a")], backwards).err(),
        Some(cert::CertError::InvalidValidity)
    );
    let unseeded = osmium_rand::SharedRng::new();
    assert_eq!(
        cert::self_signed(&unseeded, &[cert::SubjectName::Dns("a")], v).err(),
        Some(cert::CertError::NoRandomness)
    );
}

#[test]
fn pem_matches_rfc_4648_base64() {
    assert_eq!(cert::pem("X", b""), "-----BEGIN X-----\n-----END X-----\n");
    assert_eq!(cert::pem("X", b"f"), "-----BEGIN X-----\nZg==\n-----END X-----\n");
    assert_eq!(cert::pem("X", b"foobar"), "-----BEGIN X-----\nZm9vYmFy\n-----END X-----\n");
    let long = cert::pem("X", &[0u8; 60]);
    assert_eq!(long.lines().nth(1).map(str::len), Some(64));
    assert_eq!(long.lines().nth(2).map(str::len), Some(16));
}

/// Connects Python's `ssl` module (OpenSSL) to a `ServerSession` over a real
/// TCP socket. OpenSSL then checks the certificate's DER, extensions, names
/// and signature independently of rustls and webpki.
#[test]
fn openssl_client_interoperates() {
    let Ok(probe) = std::process::Command::new("python3").args(["-c", "import ssl"]).status() else {
        std::eprintln!("python3 not found; skipping");
        return;
    };
    assert!(probe.success(), "python3 has no ssl module");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs();
    let srv = server(now);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let config = srv.config.clone();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut s = ServerSession::new(config).expect("session");
        let mut buf = [0u8; 4096];
        let mut request = Vec::new();
        let mut replied = false;
        loop {
            let out = s.outgoing().to_vec();
            sock.write_all(&out).expect("send");
            s.sent(out.len());
            if s.is_closed() {
                break;
            }
            let n = sock.read(&mut buf).expect("recv");
            if n == 0 {
                break;
            }
            s.receive(&buf[..n]).expect("tls");
            request.extend(drain_server(&mut s));
            if !replied && request.ends_with(b"\r\n\r\n") {
                s.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").expect("write");
                s.close().expect("close");
                replied = true;
            }
        }
        request
    });
    let script = r#"
import socket, ssl, sys
ctx = ssl.create_default_context(cadata=sys.argv[2])
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
with socket.create_connection(("127.0.0.1", int(sys.argv[1]))) as raw:
    with ctx.wrap_socket(raw, server_hostname="hyperon.test") as tls:
        tls.sendall(b"GET / HTTP/1.1\r\nHost: hyperon.test\r\n\r\n")
        body = b""
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            body += chunk
        print(tls.version(), tls.cipher()[0], body.split(b"\r\n\r\n")[1].decode())
"#;
    let pem = cert::pem("CERTIFICATE", &srv.cert);
    let out = std::process::Command::new("python3")
        .args(["-c", script, &port.to_string(), &pem])
        .output()
        .expect("run python3");
    let request = server.join().expect("server thread");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "python failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout.trim(), "TLSv1.3 TLS_CHACHA20_POLY1305_SHA256 hello");
    assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
}

#[test]
fn utc_and_generalized_time() {
    // 2049-12-31T23:59:59Z is the last UTCTime; a second later is GeneralizedTime.
    let a = cert::self_signed(
        rng(),
        &[cert::SubjectName::Dns("a")],
        cert::Validity { not_before: 2_524_607_999, not_after: 2_524_608_000 },
    )
    .expect("certificate");
    let der = &a.cert_der;
    let find = |needle: &[u8]| der.windows(needle.len()).any(|w| w == needle);
    assert!(find(b"\x17\x0d491231235959Z"));
    assert!(find(b"\x18\x0f20500101000000Z"));
}

#[test]
fn self_test_passes_on_the_host() {
    self_test(rng(), NOW).expect("self-test");
}

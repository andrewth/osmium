use std::string::{String, ToString};
use std::vec::Vec;
use std::{format, vec};

use super::*;

/// Feeds `input` and answers every request with its method, path and body
/// echoed back. Returns the requests (or errors) and everything sent.
fn serve(input: &[u8]) -> (Vec<Result<Request, HttpError>>, String) {
    serve_split(&[input])
}

fn serve_split(pieces: &[&[u8]]) -> (Vec<Result<Request, HttpError>>, String) {
    let mut conn = Connection::new(Limits { max_head: 512, max_headers: 8, max_body: 64 });
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for piece in pieces {
        conn.receive(piece);
        while let Some(r) = conn.next_request() {
            if let Ok(req) = &r {
                let body = format!("{} {} {}", req.method.as_str(), req.path(), String::from_utf8_lossy(&req.body));
                conn.respond(Response::text(200, &body));
            }
            seen.push(r);
        }
        out.extend_from_slice(conn.outgoing());
        let n = conn.outgoing().len();
        conn.sent(n);
    }
    (seen, String::from_utf8(out).expect("responses are ASCII"))
}

fn status_of(input: &[u8]) -> u16 {
    match serve(input).0.as_slice() {
        [Err(e)] => e.status(),
        [Ok(_)] => 200,
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn simple_get() {
    let (reqs, out) = serve(b"GET /a/b?x=1&y=two+words HTTP/1.1\r\nHost: h\r\nAccept: */*\r\n\r\n");
    let req = reqs[0].as_ref().expect("request");
    assert_eq!(req.method, Method::Get);
    assert_eq!(req.path(), "/a/b");
    assert_eq!(req.query_param("y").as_deref(), Some("two words"));
    assert_eq!(req.header("ACCEPT"), Some("*/*"));
    assert!(req.keep_alive());
    assert_eq!(out, "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 9\r\n\r\nGET /a/b ");
}

#[test]
fn content_length_body() {
    let (reqs, out) = serve(b"POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello");
    assert_eq!(reqs[0].as_ref().expect("request").body, b"hello");
    assert!(out.ends_with("POST /p hello"));
}

#[test]
fn chunked_body_with_extensions_and_trailers() {
    let (reqs, _) = serve(
        b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n\
          5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n",
    );
    assert_eq!(reqs[0].as_ref().expect("request").body, b"hello world");
}

#[test]
fn byte_at_a_time_gives_the_same_result() {
    let input: &[u8] = b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n\
                         GET /next HTTP/1.1\r\nHost: h\r\n\r\n";
    let whole = serve(input);
    let pieces: Vec<&[u8]> = input.chunks(1).collect();
    let split = serve_split(&pieces);
    assert_eq!(whole, split);
    assert_eq!(whole.0.len(), 2);
}

#[test]
fn pipelined_requests_are_answered_in_order() {
    let (reqs, out) = serve(b"GET /1 HTTP/1.1\r\nHost: h\r\n\r\nGET /2 HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(reqs.len(), 2);
    let first = out.find("GET /1").expect("first");
    let second = out.find("GET /2").expect("second");
    assert!(first < second);
}

#[test]
fn requests_wait_for_the_previous_response() {
    let mut conn = Connection::new(Limits::default());
    conn.receive(b"GET /1 HTTP/1.1\r\nHost: h\r\n\r\nGET /2 HTTP/1.1\r\nHost: h\r\n\r\n");
    let first = conn.next_request().expect("one").expect("ok");
    assert_eq!(first.path(), "/1");
    assert!(conn.next_request().is_none(), "the second waits for a response to the first");
    conn.respond(Response::new(204));
    assert_eq!(conn.next_request().expect("two").expect("ok").path(), "/2");
}

#[test]
fn connection_close_and_http_1_0() {
    let mut conn = Connection::new(Limits::default());
    conn.receive(b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\nGET /ignored HTTP/1.1\r\nHost: h\r\n\r\n");
    conn.next_request().expect("one").expect("ok");
    conn.respond(Response::new(204));
    assert!(conn.should_close());
    assert!(conn.next_request().is_none(), "nothing after close");
    assert!(String::from_utf8_lossy(conn.outgoing()).contains("Connection: close\r\n"));

    let (_, out) = serve(b"GET / HTTP/1.0\r\n\r\n");
    assert!(out.contains("Connection: close\r\n"), "1.0 closes by default");
    let (_, out) = serve(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
    assert!(!out.contains("Connection: close"));
}

#[test]
fn head_gets_the_length_but_no_body() {
    let (_, out) = serve(b"HEAD /x HTTP/1.1\r\nHost: h\r\n\r\n");
    assert!(out.ends_with("Content-Length: 8\r\n\r\n"), "{out:?}");
}

#[test]
fn expect_100_continue() {
    let mut conn = Connection::new(Limits::default());
    conn.receive(b"PUT /f HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n");
    assert!(conn.next_request().is_none());
    assert_eq!(conn.outgoing(), b"HTTP/1.1 100 Continue\r\n\r\n");
    assert!(conn.next_request().is_none());
    assert_eq!(conn.outgoing().len(), 25, "sent once");
    conn.receive(b"abc");
    assert_eq!(conn.next_request().expect("request").expect("ok").body, b"abc");
}

#[test]
fn smuggling_shapes_are_refused() {
    // Both framings.
    assert_eq!(
        status_of(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        400
    );
    // Conflicting lengths, as two fields and as a list.
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd"), 400);
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3, 4\r\n\r\nabcd"), 400);
    // The same length twice is fine.
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3, 3\r\n\r\nabc"), 200);
    // Signs, spaces and hex in a length.
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: +3\r\n\r\nabc"), 400);
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0x3\r\n\r\nabc"), 400);
    // Whitespace before the colon, and folding.
    assert_eq!(status_of(b"GET / HTTP/1.1\r\nHost: h\r\nX-A : b\r\n\r\n"), 400);
    assert_eq!(status_of(b"GET / HTTP/1.1\r\nHost: h\r\nX-A: b\r\n c\r\n\r\n"), 400);
    // Bare CR and bare LF inside the head.
    assert_eq!(status_of(b"GET / HTTP/1.1\r\nHost: h\rX: y\r\n\r\n"), 400);
    assert_eq!(status_of(b"GET / HTTP/1.1\r\nHost: h\nX: y\r\n\r\n"), 400);
    // Transfer codings other than chunked, and chunked in HTTP/1.0.
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"), 501);
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"), 501);
    assert_eq!(status_of(b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"), 400);
    // Malformed chunks.
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n"), 400);
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n"), 400);
    assert_eq!(
        status_of(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffff\r\n"),
        400
    );
}

#[test]
fn malformed_requests() {
    assert_eq!(status_of(b"GET / HTTP/1.1\r\n\r\n"), 400, "no Host");
    assert_eq!(status_of(b"GET  / HTTP/1.1\r\nHost: h\r\n\r\n"), 400, "double space");
    assert_eq!(status_of(b"GET relative HTTP/1.1\r\nHost: h\r\n\r\n"), 400);
    assert_eq!(status_of(b"G(T / HTTP/1.1\r\nHost: h\r\n\r\n"), 400);
    assert_eq!(status_of(b"GET / HTTP/2.0\r\nHost: h\r\n\r\n"), 505);
    assert_eq!(status_of(b"GET / FTP/1.1\r\nHost: h\r\n\r\n"), 400);
    assert_eq!(status_of(b"GET / HTTP/1.1\r\nHost: h\r\nX: a\x01b\r\n\r\n"), 400);
    assert_eq!(status_of(b"GET / HTTP/1.1\r\nHost: h\r\nNoColon\r\n\r\n"), 400);
    assert_eq!(status_of(b"\r\n\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n"), 200, "leading empty lines are skipped");
}

#[test]
fn limits() {
    let big_head = format!("GET / HTTP/1.1\r\nHost: h\r\nX: {}\r\n\r\n", "a".repeat(600));
    assert_eq!(status_of(big_head.as_bytes()), 431);
    let many: String = (0..9).map(|i| format!("X-{i}: v\r\n")).collect();
    assert_eq!(status_of(format!("GET / HTTP/1.1\r\nHost: h\r\n{many}\r\n").as_bytes()), 431);
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 65\r\n\r\n"), 413);
    assert_eq!(status_of(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999999999999999\r\n\r\n"), 413);
    let chunks = "a\r\n0123456789\r\n".repeat(7);
    assert_eq!(
        status_of(
            format!("POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}0\r\n\r\n").as_bytes()
        ),
        413
    );
    // An unterminated head is refused once it passes the limit, not buffered forever.
    let mut conn = Connection::new(Limits { max_head: 512, max_headers: 8, max_body: 64 });
    conn.receive(&[b'a'; 600]);
    assert_eq!(conn.next_request().map(|r| r.map(|_| ())), Some(Err(HttpError::HeadersTooLarge)));
}

#[test]
fn errors_answer_and_close() {
    let mut conn = Connection::new(Limits::default());
    conn.receive(b"BROKEN\r\n\r\n");
    assert!(matches!(conn.next_request(), Some(Err(HttpError::BadRequest(_)))));
    assert!(conn.should_close());
    let out = String::from_utf8_lossy(conn.outgoing()).to_string();
    assert!(out.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{out}");
    assert!(out.contains("Connection: close\r\n"));
    conn.receive(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
    assert!(conn.next_request().is_none());
}

#[test]
fn response_headers_cannot_break_framing() {
    let mut out = Vec::new();
    Response::text(200, "hi")
        .header("X-Evil", "a\r\nSet-Cookie: x")
        .header("Bad Name", "v")
        .header("Content-Length", "999")
        .header("Transfer-Encoding", "chunked")
        .header("X-Good", "ok")
        .write_to(&mut out, false, false);
    let out = String::from_utf8(out).expect("ascii");
    assert_eq!(
        out,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nX-Good: ok\r\nContent-Length: 2\r\n\r\nhi"
    );
}

#[test]
fn no_content_and_not_modified() {
    let mut out = Vec::new();
    Response::new(204).write_to(&mut out, false, false);
    assert_eq!(out, b"HTTP/1.1 204 No Content\r\n\r\n");
    let mut out = Vec::new();
    Response::new(304).body("text/plain", "x").write_to(&mut out, false, false);
    assert!(out.ends_with(b"Content-Length: 1\r\n\r\n"), "304 keeps the length but drops the body");
}

#[test]
fn path_segments_and_decoding() {
    let req = |t: &str| Request {
        method: Method::Get,
        target: t.into(),
        version: Version::Http11,
        headers: vec![],
        body: vec![],
    };
    assert_eq!(req("/vms/web%201/start?x").segments(), Some(vec!["vms".into(), "web 1".into(), "start".into()]));
    assert_eq!(req("//a///b/").segments(), Some(vec!["a".into(), "b".into()]));
    assert_eq!(req("/a/%2e%2e/b").segments(), None, "encoded ..");
    assert_eq!(req("/a/../b").segments(), None);
    assert_eq!(req("/a%2fb").segments(), None, "encoded slash");
    assert_eq!(req("/a%zz").segments(), None);
    assert_eq!(url::percent_decode("%e2%9c%93"), Some("✓".into()));
    assert_eq!(url::percent_decode("%ff"), None, "not UTF-8");
    let pairs: Vec<_> = url::query_pairs("a=1&&b=x+y&c&d=%3D").collect();
    assert_eq!(
        pairs,
        vec![("a".into(), "1".into()), ("b".into(), "x y".into()), ("c".into(), "".into()), ("d".into(), "=".into())]
    );
}

#[test]
fn content_types() {
    assert_eq!(content_type("/index.HTML"), "text/html; charset=utf-8");
    assert_eq!(content_type("app.js"), "text/javascript; charset=utf-8");
    assert_eq!(content_type("noext"), "application/octet-stream");
}

/// Runs `script` with Python, passing `args`. `None` when Python is missing.
fn python(script: &str, args: &[&str]) -> Option<std::process::Output> {
    let mut cmd = std::process::Command::new("python3");
    cmd.arg("-c").arg(script).args(args);
    match cmd.output() {
        Ok(out) => Some(out),
        Err(_) => {
            std::eprintln!("python3 not found; skipping");
            None
        }
    }
}

#[test]
fn python_http_client_interoperates() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut conn = Connection::new(Limits::default());
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = sock.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            conn.receive(&buf[..n]);
            while let Some(Ok(req)) = conn.next_request() {
                seen.push(format!("{} {} {}", req.method.as_str(), req.target, req.body.len()));
                let resp = match req.path() {
                    "/echo" => Response::new(200).body("application/octet-stream", req.body.clone()),
                    _ => Response::text(200, "root\n"),
                };
                conn.respond(resp);
            }
            let out = conn.outgoing().to_vec();
            sock.write_all(&out).expect("send");
            conn.sent(out.len());
            if conn.should_close() {
                break;
            }
        }
        seen
    });
    let script = r#"
import http.client, sys
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]))
c.request("GET", "/")
r = c.getresponse(); a = r.read()
c.request("POST", "/echo", body=b"x" * 100000)
r2 = c.getresponse(); b = r2.read()
def gen():
    yield b"chunk-one,"
    yield b"chunk-two"
c.request("POST", "/echo", body=gen(), encode_chunked=True, headers={"Transfer-Encoding": "chunked"})
r3 = c.getresponse(); d = r3.read()
c.request("HEAD", "/")
r4 = c.getresponse(); e = r4.read()
c.request("GET", "/", headers={"Connection": "close"})
r5 = c.getresponse(); f = r5.read()
print(r.status, a.decode().strip(), len(b), d.decode(), r4.getheader("Content-Length"), len(e), f.decode().strip())
"#;
    let Some(out) = python(script, &[&port.to_string()]) else { return };
    let seen = server.join().expect("server");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "200 root 100000 chunk-one,chunk-two 5 0 root");
    assert_eq!(seen, ["GET / 0", "POST /echo 100000", "POST /echo 19", "HEAD / 0", "GET / 0"]);
}

#[test]
fn https_through_osmium_tls() {
    use std::io::{Read, Write};
    static RNG: osmium_rand::SharedRng = osmium_rand::SharedRng::new();
    RNG.seed(&osmium_rand::CpuEntropy).expect("entropy");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs();
    let names = [osmium_tls::cert::SubjectName::Dns("hyperon.test")];
    let validity = osmium_tls::cert::Validity { not_before: now - 86_400, not_after: now + 86_400 };
    let id = osmium_tls::cert::self_signed(&RNG, &names, validity).expect("cert");
    let pem = osmium_tls::cert::pem("CERTIFICATE", &id.cert_der);
    let config = osmium_tls::server_config(
        osmium_tls::shared_provider(&RNG),
        std::sync::Arc::new(osmium_tls::FixedTime(now)),
        vec![id.cert_der.clone().into()],
        osmium_tls::rustls::pki_types::PrivateKeyDer::Pkcs8(id.key_pkcs8_der.clone().into()),
    )
    .expect("config");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut tls = osmium_tls::ServerSession::new(config).expect("session");
        let mut http = Connection::new(Limits::default());
        let mut buf = [0u8; 4096];
        let mut served = 0;
        loop {
            let n = sock.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            if tls.receive(&buf[..n]).is_err() {
                break;
            }
            let mut plain = vec![0u8; tls.readable()];
            let got = tls.read(&mut plain);
            http.receive(&plain[..got]);
            while let Some(Ok(req)) = http.next_request() {
                served += 1;
                http.respond(Response::json(200, &format!("{{\"path\":\"{}\"}}", req.path())));
            }
            let out = http.outgoing().to_vec();
            http.sent(out.len());
            if !out.is_empty() {
                tls.write(&out).expect("tls write");
            }
            if http.should_close() && !tls.is_closed() {
                tls.close().expect("close");
            }
            let wire = tls.outgoing().to_vec();
            sock.write_all(&wire).expect("send");
            tls.sent(wire.len());
            if tls.is_closed() {
                break;
            }
        }
        served
    });
    let script = r#"
import ssl, sys, urllib.request, json
ctx = ssl.create_default_context(cadata=sys.argv[2])
ctx.check_hostname = True
handler = urllib.request.HTTPSHandler(context=ctx)
# Resolve hyperon.test to the test server without touching DNS.
import socket
orig = socket.getaddrinfo
socket.getaddrinfo = lambda host, *a, **k: orig("127.0.0.1" if host == "hyperon.test" else host, *a, **k)
with urllib.request.build_opener(handler).open("https://hyperon.test:%s/vms/list" % sys.argv[1]) as r:
    print(r.status, json.load(r)["path"], r.headers["Content-Type"])
"#;
    let Some(out) = python(script, &[&port.to_string(), &pem]) else { return };
    let served = server.join().expect("server");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "200 /vms/list application/json");
    assert_eq!(served, 1);
}

#[test]
fn receive_buffers_at_most_one_request_and_resumes_after_a_response() {
    let limits = Limits { max_head: 512, max_headers: 8, max_body: 64 };
    let mut conn = Connection::new(limits);
    let one = b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n";
    let many: Vec<u8> = one.iter().copied().cycle().take(one.len() * 100).collect();
    let mut offered = &many[..];
    let mut answered = 0;
    while !offered.is_empty() {
        let took = conn.receive(offered);
        assert!(took > 0 || conn.is_awaiting_response() || conn.next_request().is_some(), "stalled");
        offered = &offered[took..];
        while let Some(req) = conn.next_request() {
            req.expect("ok");
            conn.respond(Response::new(204));
            answered += 1;
        }
        let n = conn.outgoing().len();
        conn.sent(n);
    }
    while let Some(req) = conn.next_request() {
        req.expect("ok");
        conn.respond(Response::new(204));
        answered += 1;
    }
    assert_eq!(answered, 100);
}

#[test]
fn chunked_body_trickling_in() {
    let mut conn = Connection::new(Limits::default());
    conn.receive(b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n");
    let mut expect = Vec::new();
    for i in 0..500u32 {
        let data = format!("piece {i};");
        expect.extend_from_slice(data.as_bytes());
        conn.receive(format!("{:x}\r\n{data}\r\n", data.len()).as_bytes());
        assert!(conn.next_request().is_none());
    }
    conn.receive(b"0\r\n\r\n");
    assert_eq!(conn.next_request().expect("request").expect("ok").body, expect);
}

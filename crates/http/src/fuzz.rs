//! Deterministic fuzzing of the request parser and the chunked decoder.
//!
//! A fixed-seed generator mutates well-formed requests and builds random
//! chunked bodies, so every run checks the same inputs and a failure can be
//! replayed. The properties checked: nothing panics, a complete request never
//! claims more bytes than it was given or a body over the limit, the result
//! doesn't depend on how the bytes were split, the connection never stalls
//! with a full buffer, and chunked decoding round-trips.

use std::format;
use std::vec::Vec;

use crate::request::{self, Parsed};
use crate::{Connection, HttpError, Limits, Request, Response};

/// xorshift64*: small, fast and fixed, so the inputs never change.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

const LIMITS: Limits = Limits { max_head: 512, max_headers: 8, max_body: 64 };

const SEEDS: &[&[u8]] = &[
    b"GET /a/b?x=1 HTTP/1.1\r\nHost: h\r\nAccept: */*\r\n\r\n",
    b"POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
    b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5;e=1\r\nhello\r\n6\r\n world\r\n0\r\nT: t\r\n\r\n",
    b"GET http://h:80/abs?q HTTP/1.1\r\nHost: h\r\n\r\nGET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    b"PUT /x HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc\r\nGET /y HTTP/1.1\r\nHost: h\r\n\r\n",
];

/// Bytes that matter to the parser, so mutations hit its decisions.
const INTERESTING: &[u8] = b"\r\n\r\n :;,\t0123456789abcdefABCDEF/?%*\x00\x7f\xff";

fn mutate(rng: &mut Rng, input: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(4) {
        let at = rng.below(input.len() + 1);
        match rng.below(7) {
            0 if at < input.len() => input[at] = *rng.pick(INTERESTING),
            1 if at < input.len() => input[at] ^= 1 << rng.below(8),
            2 => input.insert(at, *rng.pick(INTERESTING)),
            3 if at < input.len() => {
                input.remove(at);
            }
            4 => {
                let end = (at + rng.below(16)).min(input.len());
                let copy = input[at..end].to_vec();
                let to = rng.below(input.len() + 1);
                input.splice(to..to, copy);
            }
            5 => {
                let words: &[&[u8]] = &[
                    b"\r\nTransfer-Encoding: chunked",
                    b"\r\nContent-Length: 2",
                    b"\r\nContent-Length: 99999999999999999999",
                    b"ffffffffffffffff\r\n",
                    b"0\r\n\r\n",
                    b";ext=\"v\"",
                    b"\r\n ",
                    b"HTTP/1.1",
                ];
                input.splice(at..at, rng.pick(words).iter().copied());
            }
            _ => input.truncate(at),
        }
    }
}

/// Checks the parser on `buf` and on prefixes of it.
fn check_parse(rng: &mut Rng, buf: &[u8]) {
    match request::parse(buf, &LIMITS) {
        Ok(Parsed::Complete(req, used)) => {
            assert!(used <= buf.len(), "used {used} of {} bytes: {buf:?}", buf.len());
            assert!(req.body.len() <= LIMITS.max_body, "{buf:?}");
            // The request is the same seen through exactly the bytes it used...
            match request::parse(&buf[..used], &LIMITS) {
                Ok(Parsed::Complete(again, n)) => assert!(again == req && n == used, "{buf:?}"),
                other => panic!("prefix of a complete request gave {other:?}: {buf:?}"),
            }
            // ...and any shorter prefix is just incomplete, never complete or an error.
            let cut = rng.below(used);
            match request::parse(&buf[..cut], &LIMITS) {
                Ok(Parsed::Incomplete { .. }) => {}
                other => panic!("{cut}-byte prefix gave {other:?}: {buf:?}"),
            }
            // The accessors must cope with whatever target got through.
            let _ = (req.path(), req.query(), req.authority(), req.segments(), req.keep_alive());
        }
        Ok(Parsed::Incomplete { .. }) => {
            let cut = rng.below(buf.len() + 1);
            match request::parse(&buf[..cut], &LIMITS) {
                Ok(Parsed::Incomplete { .. }) => {}
                other => panic!("{cut}-byte prefix of an incomplete request gave {other:?}: {buf:?}"),
            }
        }
        Err(_) => {}
    }
}

/// Feeds `input` to a connection in pieces whose sizes come from `rng`,
/// answering every request. Returns what came out of `next_request`.
fn serve(rng: Option<&mut Rng>, input: &[u8]) -> Vec<Result<Request, HttpError>> {
    let mut rng = rng;
    let mut conn = Connection::new(LIMITS);
    let mut seen = Vec::new();
    let mut offset = 0;
    loop {
        let piece = match rng.as_deref_mut() {
            Some(r) => 1 + r.below(64),
            None => input.len(),
        };
        let end = (offset + piece).min(input.len());
        let took = conn.receive(&input[offset..end]);
        offset += took;
        let mut answered = false;
        while let Some(r) = conn.next_request() {
            if let Ok(req) = &r {
                assert!(req.body.len() <= LIMITS.max_body);
                conn.respond(Response::text(200, req.path()));
            }
            seen.push(r);
            answered = true;
        }
        let out = conn.outgoing().len();
        if out > 0 {
            assert!(conn.outgoing().starts_with(b"HTTP/1.1 "), "{:?}", conn.outgoing());
        }
        conn.sent(out);
        if offset == input.len() {
            return seen;
        }
        // The buffer is full and nothing can be answered: a stall.
        assert!(took > 0 || answered || conn.should_close(), "connection stalled on {input:?}");
    }
}

#[test]
fn mutated_requests_parse_consistently() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for round in 0..20_000 {
        let mut input = rng.pick(SEEDS).to_vec();
        mutate(&mut rng, &mut input);
        check_parse(&mut rng, &input);
        if round % 4 == 0 {
            // However the bytes are split, the connection sees the same requests.
            let whole = serve(None, &input);
            let split = serve(Some(&mut rng), &input);
            assert_eq!(whole, split, "{input:?}");
        }
    }
}

#[test]
fn random_bytes_never_panic_or_stall() {
    let mut rng = Rng(0xfeed_f00d_dead_beef);
    for _ in 0..5_000 {
        let len = rng.below(600);
        let input: Vec<u8> =
            (0..len).map(|_| if rng.below(2) == 0 { *rng.pick(INTERESTING) } else { rng.next() as u8 }).collect();
        check_parse(&mut rng, &input);
        serve(Some(&mut rng), &input);
    }
}

/// Encodes `body` with random chunk sizes, size spellings, extensions and
/// trailers, then checks that decoding gives `body` back however it arrives.
#[test]
fn chunked_bodies_round_trip() {
    let mut rng = Rng(0x5eed_0000_0000_0001);
    for _ in 0..5_000 {
        let body: Vec<u8> = (0..rng.below(LIMITS.max_body + 1)).map(|_| rng.next() as u8).collect();
        let mut wire = Vec::from(&b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"[..]);
        let mut rest = &body[..];
        while !rest.is_empty() {
            let n = (1 + rng.below(20)).min(rest.len());
            let size = match rng.below(3) {
                0 => format!("{n:x}"),
                1 => format!("{n:X}"),
                _ => format!("{n:08x}"),
            };
            let ext = if rng.below(3) == 0 { ";name=value" } else { "" };
            wire.extend_from_slice(format!("{size}{ext}\r\n").as_bytes());
            wire.extend_from_slice(&rest[..n]);
            wire.extend_from_slice(b"\r\n");
            rest = &rest[n..];
        }
        wire.extend_from_slice(b"0\r\n");
        for i in 0..rng.below(3) {
            wire.extend_from_slice(format!("X-T{i}: v\r\n").as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        match request::parse(&wire, &LIMITS) {
            Ok(Parsed::Complete(req, used)) => {
                assert_eq!(req.body, body);
                assert_eq!(used, wire.len());
            }
            other => panic!("{other:?} for {wire:?}"),
        }
        let seen = serve(Some(&mut rng), &wire);
        match seen.as_slice() {
            [Ok(req)] => assert_eq!(req.body, body),
            other => panic!("{other:?} for {wire:?}"),
        }
    }
}

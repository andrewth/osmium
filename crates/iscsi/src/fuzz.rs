//! Garbage in, no panic out: every parser fed random, truncated and mutated bytes from a fixed seed.

use std::string::String;
use std::vec::Vec;

use crate::chap::{self, Chap};
use crate::params::{Negotiator, Offer};
use crate::pdu::{BHS_LEN, Message, Pdu, PduReader};
use crate::scsi::{Capacity, Inquiry, Sense, rw_range};
use crate::text;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn upto(&mut self, max: usize) -> Vec<u8> {
        let n = self.next() as usize % max;
        self.bytes(n)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// Opcodes the decoder knows, so garbage reaches each variant's field extraction.
const OPCODES: [u8; 18] =
    [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x31, 0x32, 0x3f];

#[test]
fn pdu_reader_and_decoder_survive_garbage() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for round in 0..3000 {
        let mut reader = PduReader::new(if round % 2 == 0 { 4096 } else { usize::MAX });
        reader.set_digests(round % 3 == 0, round % 5 == 0);
        let mut stream = rng.upto(400);
        if let Some(op) = stream.first_mut() {
            *op = OPCODES[rng.next() as usize % OPCODES.len()];
        }
        // Feed it in pieces, as a TCP stream arrives.
        for piece in stream.chunks(1 + rng.next() as usize % 97) {
            reader.push(piece);
            loop {
                match reader.next_pdu() {
                    Ok(Some(pdu)) => {
                        let _ = Message::decode(pdu);
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }
}

#[test]
fn decode_and_round_trip_every_opcode() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for &op in &OPCODES {
        for _ in 0..200 {
            let mut pdu = Pdu::new(op);
            let junk = rng.bytes(BHS_LEN);
            pdu.bhs.copy_from_slice(&junk);
            pdu.bhs[0] = op | (pdu.bhs[0] & 0x40);
            pdu.data = rng.upto(40);
            if let Ok(m) = Message::decode(pdu) {
                let again = m.clone().encode();
                assert_eq!(Message::decode(again).ok(), Some(m));
            }
        }
    }
}

#[test]
fn scsi_parsers_survive_garbage() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for _ in 0..20000 {
        let d = rng.upto(70);
        let _ = Sense::parse(&d);
        let _ = Sense::from_response(&d);
        let _ = Inquiry::parse(&d);
        let _ = Capacity::parse_10(&d);
        let _ = Capacity::parse_16(&d);
        let _ = rw_range(&d);
        if let Some(c) = Capacity::parse_16(&d) {
            let _ = c.blocks();
        }
    }
    // The largest claimed capacity must not overflow.
    assert_eq!(Capacity { last_lba: u64::MAX, block_size: 512 }.blocks(), u64::MAX);
}

#[test]
fn text_and_negotiation_survive_garbage() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let keys = [
        "MaxBurstLength",
        "FirstBurstLength",
        "MaxRecvDataSegmentLength",
        "HeaderDigest",
        "DataDigest",
        "InitialR2T",
        "ImmediateData",
        "DefaultTime2Wait",
        "AuthMethod",
        "CHAP_A",
        "CHAP_I",
        "CHAP_C",
        "CHAP_R",
        "TargetPortalGroupTag",
    ];
    let values = [
        "0",
        "1",
        "512",
        "0xffffffff",
        "18446744073709551615",
        "-1",
        "Yes",
        "No",
        "CRC32C",
        "None",
        "0x",
        "0b",
        "0bAA==",
    ];
    for _ in 0..5000 {
        let raw = rng.upto(60);
        let _ = text::parse(&raw);
        let _ = chap::decode_binary(&String::from_utf8_lossy(&raw));
        let mut data = Vec::new();
        for _ in 0..rng.next() % 6 {
            text::push(&mut data, keys[rng.next() as usize % keys.len()], values[rng.next() as usize % values.len()]);
        }
        let mut n = Negotiator::new(Offer::default());
        let _ = n.security_keys("iqn.init", Some("iqn.target"), rng.next() % 2 == 0);
        let _ = n.operational_keys(rng.next() % 2 == 0);
        let _ = n.respond(&data);
        let _ = n.respond(&raw);
        let _ = n.finish();
        if let Some(pairs) = text::parse(&data) {
            let c = Chap::new("user", b"0123456789abcdef").mutual("tgt", b"fedcba9876543210", [9; 16]);
            if let Ok((_, expected)) = chap::answer(&c, &pairs) {
                let _ = chap::verify(&c, expected, &pairs);
            }
        }
    }
}

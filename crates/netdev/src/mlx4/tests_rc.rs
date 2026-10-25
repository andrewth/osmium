//! Reliable connections against the simulated HCA: two queue pairs of one
//! adapter, on its two ports, connected to each other.

use std::vec::Vec;

use osmium_hal::net::NetError;

use super::fake::FakeHca;
use super::tests_ib::{IB, QKEY, bring_up};
use super::*;
use osmium_drivers::virtio::testing::HostDma;

type Port<'h, 'd> = IbPort<'h, 'd, HostDma>;

/// Two ports, each with a connection, connected to each other.
struct Pair<'h, 'd> {
    a: Port<'h, 'd>,
    b: Port<'h, 'd>,
    ca: RcId,
    cb: RcId,
    ia: RcInfo,
    ib: RcInfo,
}

const A_PSN: u32 = 100;
const B_PSN: u32 = 200;

fn params(to_lid: u16, to_qpn: u32, send: u32, receive: u32) -> RcParams {
    RcParams { send_psn: send, receive_psn: receive, ..RcParams::to(to_lid, to_qpn) }
}

fn pair<'h, 'd>(mlx: &'h Mlx4<'d, HostDma>, hca: &FakeHca) -> Pair<'h, 'd> {
    let (mut a, mut b) = (mlx.open_ib(1, QKEY).unwrap(), mlx.open_ib(2, QKEY).unwrap());
    hca.sm_configure(1, 7);
    hca.sm_configure(2, 8);
    let ((ca, ia), (cb, ib)) = (a.rc_create().unwrap(), b.rc_create().unwrap());
    a.rc_connect(ca, &params(8, ib.qpn, A_PSN, B_PSN)).unwrap();
    b.rc_connect(cb, &params(7, ia.qpn, B_PSN, A_PSN)).unwrap();
    Pair { a, b, ca, cb, ia, ib }
}

/// Lets `a`'s operations run and returns what `a` then reports.
fn finish(hca: &FakeHca, p: &mut Pair<'_, '_>, buf: &mut [u8]) -> Option<RcEvent> {
    hca.rc_run(p.ia.qpn);
    p.a.rc_poll(p.ca, buf)
}

#[test]
fn connections_are_made_with_the_right_parameters() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let before = dma.live.get();
    let mut p = pair(&mlx, &hca);
    // Queue pair numbers after the special ones and the data queue pairs; one number per port.
    assert_eq!((p.ia.qpn, p.ib.qpn), (74, 75));
    assert_eq!((p.a.rc_state(p.ca), p.b.rc_state(p.cb)), (Some(RcState::Connected), Some(RcState::Connected)));

    let c = hca.rc_ctx(p.ia.qpn);
    assert_eq!(
        (c.pkey_index, c.init_access, c.access),
        (0, 0b010, 0b110),
        "writes first, reads with responder resources"
    );
    assert_eq!((c.remote_qpn, c.dlid, c.grh, c.path_bits, c.sched_queue), (75, 8, false, 0, 0x83));
    assert_eq!((c.mtu_bytes, c.max_dest_rd_log, c.max_rd_log), (2048, 2, 2));
    assert_eq!(
        (c.rq_psn, c.min_rnr_timer, c.ack_timeout, c.retry, c.rnr_retry, c.sq_psn),
        (B_PSN, 12, 14, 7, 7, A_PSN)
    );
    let c = hca.rc_ctx(p.ib.qpn);
    assert_eq!((c.remote_qpn, c.dlid, c.sched_queue, c.rq_psn, c.sq_psn), (74, 7, 0x83 | 1 << 6, A_PSN, B_PSN));

    // The window is its own memory region; the all-memory one has no remote access.
    {
        let s = hca.state.borrow();
        assert_eq!(s.fw.mrs.len(), 3);
        let global = &s.fw.mrs[&16];
        assert_eq!((global.access, global.start, global.len), (3 << 10, 0, u64::MAX));
        let window = &s.fw.mrs[&17];
        assert_eq!((window.access, window.start, window.len), (0xf << 10, p.ia.window.addr, WINDOW_LEN as u64));
        assert_eq!(window.key.rotate_left(8), p.ia.window.rkey);
        assert_ne!(p.ia.window.rkey, mlx.lkey, "a key of its own");
        assert_eq!(s.fw.mrs[&18].start, p.ib.window.addr);
    }
    assert_eq!(p.a.rc_window(p.ca), Some(p.ia.window));

    // Connecting is once only, and cleanly refused for what the port cannot do.
    let again = params(8, p.ib.qpn, 0, 0);
    assert_eq!(p.a.rc_connect(p.ca, &again), Err(Mlx4Error::BadParameter), "already connected");
    let (c3, _) = p.a.rc_create().unwrap();
    for bad in [
        RcParams { path_mtu: 0, ..again },
        RcParams { path_mtu: 6, ..again },
        RcParams { sl: 16, ..again },
        RcParams { path_bits: 128, ..again },
        RcParams { retry_count: 8, ..again },
        RcParams { rnr_retry: 8, ..again },
        RcParams { min_rnr_timer: 32, ..again },
        RcParams { ack_timeout: 32, ..again },
        RcParams { dest_qpn: 1 << 24, ..again },
        RcParams { send_psn: 1 << 24, ..again },
        RcParams { max_rd_atomic: 65, ..again },
        RcParams { max_dest_rd_atomic: 65, ..again },
        RcParams {
            route: Some(Route { dgid: Gid::default(), sgid_index: 8, hop_limit: 1, traffic_class: 0, flow_label: 0 }),
            ..again
        },
    ] {
        assert_eq!(p.a.rc_connect(c3, &bad), Err(Mlx4Error::BadParameter), "{bad:?}");
    }
    assert_eq!(p.a.rc_state(c3), Some(RcState::Unconnected), "refused before anything was sent to the adapter");
    // Nothing to do on a connection that is not connected, or does not exist.
    assert_eq!(p.a.rc_send(c3, b"x"), Err(NetError::Io));
    assert_eq!(p.a.rc_send(RcId(3), b"x"), Err(NetError::Io));
    assert_eq!(p.a.rc_poll(c3, &mut [0; 8]), None);

    // A route that crosses subnets is passed on.
    let route = Route {
        dgid: Gid::new(0xfe80_0000_0000_0099, 0x1122_3344_5566_7788),
        sgid_index: 3,
        hop_limit: 9,
        traffic_class: 0x44,
        flow_label: 0xa_bcde,
    };
    p.a.rc_connect(c3, &RcParams { route: Some(route), sl: 5, path_bits: 1, ..again }).unwrap();
    let c = hca.rc_ctx(76);
    assert_eq!((c.grh, c.path_bits, c.sgid_index, c.hop_limit, c.dgid), (true, 1, 3, 9, route.dgid.0));
    assert_eq!((c.tclass_flow, c.sched_queue), (0x44 << 20 | 0xa_bcde, 0x83 | 5 << 2));

    // Four connections to a port; destroying one makes room for another.
    let extra: Vec<_> = (0..2).map(|_| p.a.rc_create().unwrap().0).collect();
    assert_eq!(p.a.rc_create().err(), Some(Mlx4Error::NoMemory));
    p.a.rc_destroy(extra[0]);
    assert_eq!(
        hca.qps().len(),
        (3 + 3) + (3 + 1),
        "port 1: queue pairs 0 and 1, data, three connections; port 2: the same with one"
    );
    p.a.rc_create().unwrap();

    drop(p);
    assert!(hca.qps().is_empty() && hca.state.borrow().fw.mrs.len() <= 1);
    assert_eq!(dma.live.get(), before);
}

#[test]
fn messages_flow_both_ways() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut p = pair(&mlx, &hca);
    let mut buf = [0u8; 8192];

    p.a.rc_send(p.ca, b"hello").unwrap();
    assert_eq!(finish(&hca, &mut p, &mut buf), Some(RcEvent::Sent));
    assert_eq!(p.b.rc_poll(p.cb, &mut buf), Some(RcEvent::Received { len: 5 }));
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(p.a.rc_poll(p.ca, &mut buf), None);
    assert_eq!(p.b.rc_poll(p.cb, &mut buf), None);
    assert_eq!(hca.rc_ctx(p.ia.qpn).send_psn, A_PSN + 1);
    assert_eq!(hca.rc_ctx(p.ib.qpn).recv_psn, A_PSN + 1);

    // Both directions, sizes from nothing to a full message (several packets), around the rings several times.
    for n in 0..200u32 {
        let len = (n * 83) as usize % (MAX_MESSAGE + 1);
        let msg: Vec<u8> = (0..len).map(|i| (i as u32 + n) as u8).collect();
        let (from, to, run, from_id, to_id) = if n % 3 == 0 {
            (&mut p.b, &mut p.a, p.ib.qpn, p.cb, p.ca)
        } else {
            (&mut p.a, &mut p.b, p.ia.qpn, p.ca, p.cb)
        };
        from.rc_send(from_id, &msg).unwrap();
        hca.rc_run(run);
        assert_eq!(from.rc_poll(from_id, &mut buf), Some(RcEvent::Sent), "message {n}");
        assert_eq!(to.rc_poll(to_id, &mut buf), Some(RcEvent::Received { len }), "message {n}");
        assert_eq!(buf[..len], msg[..]);
    }
    assert_eq!(p.a.rc_send(p.ca, &[0; MAX_MESSAGE + 1]), Err(NetError::TooLarge));

    // A window's worth of sends at once: the ninth waits for the first to be reported.
    for n in 0..queue::TX_SLOTS {
        p.a.rc_send(p.ca, &[n as u8; 100]).unwrap();
    }
    assert_eq!(p.a.rc_send(p.ca, &[9; 100]), Err(NetError::WouldBlock));
    hca.rc_run(p.ia.qpn);
    assert_eq!(p.a.rc_send(p.ca, &[9; 100]), Err(NetError::WouldBlock), "completed, but not yet reported");
    for _ in 0..queue::TX_SLOTS {
        assert_eq!(p.a.rc_poll(p.ca, &mut buf), Some(RcEvent::Sent));
        assert_eq!(p.b.rc_poll(p.cb, &mut buf), Some(RcEvent::Received { len: 100 }));
    }
    p.a.rc_send(p.ca, &[9; 100]).unwrap();
}

#[test]
fn a_receiver_that_is_not_ready_is_waited_for() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut p = pair(&mlx, &hca);
    let mut buf = [0u8; 64];

    // The receiver has queue::RX_SLOTS entries; the sender does not outrun them while it retries forever.
    let mut sent = 0;
    for n in 0..2 * queue::RX_SLOTS {
        if p.a.rc_send(p.ca, &[n as u8; 8]).is_err() {
            break;
        }
        sent += 1;
        hca.rc_run(p.ia.qpn);
        if sent % queue::TX_SLOTS == 0 {
            for _ in 0..queue::TX_SLOTS {
                p.a.rc_poll(p.ca, &mut buf);
            }
        }
    }
    let stuck = hca.rc_ctx(p.ib.qpn).recv_psn - A_PSN;
    assert_eq!(stuck, queue::RX_SLOTS, "every receive entry was used, and the next send waits");
    assert_eq!(p.b.rc_poll(p.cb, &mut buf), Some(RcEvent::Received { len: 8 }));
    hca.rc_run(p.ia.qpn);
    assert_eq!(hca.rc_ctx(p.ib.qpn).recv_psn - A_PSN, queue::RX_SLOTS + 1, "a receive entry was reposted, and it went");
    assert_eq!(p.a.rc_state(p.ca), Some(RcState::Connected));

    // With a limit on the retries the same situation is a failure.
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let (mut a, mut b) = (mlx.open_ib(1, QKEY).unwrap(), mlx.open_ib(2, QKEY).unwrap());
    let ((ca, ia), (cb, ib)) = (a.rc_create().unwrap(), b.rc_create().unwrap());
    a.rc_connect(ca, &RcParams { rnr_retry: 3, ..params(8, ib.qpn, 0, 0) }).unwrap();
    b.rc_connect(cb, &params(7, ia.qpn, 0, 0)).unwrap();
    let mut events = Vec::new();
    for _ in 0..queue::RX_SLOTS + 2 {
        if a.rc_send(ca, b"x").is_ok() {
            hca.rc_run(ia.qpn);
        }
        events.extend(core::iter::from_fn(|| a.rc_poll(ca, &mut buf)));
    }
    let failed = events.iter().position(|e| matches!(e, RcEvent::Failed(_)));
    assert_eq!(failed.map(|i| events[i]), Some(RcEvent::Failed(RcFailure::RnrRetryExceeded)), "{events:?}");
    assert_eq!(
        events.iter().filter(|e| **e == RcEvent::Sent).count(),
        queue::RX_SLOTS as usize,
        "all that fit were sent"
    );
    assert_eq!(a.rc_state(ca), Some(RcState::Failed));
    assert_eq!(a.rc_send(ca, b"y"), Err(NetError::Io), "the connection is gone");
}

#[test]
fn rdma_stays_inside_the_window() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut p = pair(&mlx, &hca);
    let mut buf = [0u8; 8192];
    let w = p.ib.window;

    // Write into the peer's window, and read it back there and over the wire.
    let data: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    p.a.rc_write(p.ca, w.addr + 100, w.rkey, &data).unwrap();
    assert_eq!(finish(&hca, &mut p, &mut buf), Some(RcEvent::Written));
    let mut seen = [0u8; 3000];
    p.b.rc_window_read(p.cb, 100, &mut seen).unwrap();
    assert_eq!(seen[..], data[..]);
    assert_eq!(p.b.rc_poll(p.cb, &mut buf), None, "a plain write is invisible to the receiver");
    p.a.rc_read(p.ca, w.addr + 100, w.rkey, 3000).unwrap();
    assert_eq!(finish(&hca, &mut p, &mut buf), Some(RcEvent::Read { len: 3000 }));
    assert_eq!(buf[..3000], data[..]);
    // The other way, from what the peer put in its own window.
    p.b.rc_window_write(p.cb, 0, b"published").unwrap();
    p.a.rc_read(p.ca, w.addr, w.rkey, 9).unwrap();
    assert_eq!(finish(&hca, &mut p, &mut buf), Some(RcEvent::Read { len: 9 }));
    assert_eq!(&buf[..9], b"published");
    p.a.rc_read(p.ca, w.addr, w.rkey, 9).unwrap();
    assert_eq!(finish(&hca, &mut p, &mut buf[..4]), Some(RcEvent::Failed(RcFailure::BufferTooSmall)));
    assert_eq!(p.a.rc_state(p.ca), Some(RcState::Connected), "only the caller's buffer was wrong");

    // Our own window API is bounds-checked.
    assert_eq!(p.a.rc_window_read(p.ca, WINDOW_LEN - 1, &mut [0; 2]), Err(Mlx4Error::BadParameter));
    assert_eq!(p.a.rc_window_write(p.ca, usize::MAX, &[0; 2]), Err(Mlx4Error::BadParameter));
    assert_eq!(p.a.rc_window_write(RcId(2), 0, &[0; 2]), Err(Mlx4Error::BadParameter));

    // What the peer's key does not cover is refused, each time with the connection failing.
    let canary = [0xc3u8; 64];
    for which in 0..5 {
        let hca = FakeHca::new(IB);
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        let mut p = pair(&mlx, &hca);
        let w = p.ib.window;
        let (addr, rkey, len) = match which {
            0 => (w.addr + WINDOW_LEN as u64 - 10, w.rkey, 20),
            1 => (w.addr - 64, w.rkey, 16),
            2 => (w.addr, w.rkey ^ 1 << 8, 16),
            3 => (w.addr, mlx.lkey, 16),
            _ => (p.ia.window.addr, w.rkey, 16),
        };
        p.b.rc_window_write(p.cb, WINDOW_LEN - 64, &canary).unwrap();
        p.a.rc_write(p.ca, addr, rkey, &[0xee; 32][..len]).unwrap();
        p.a.rc_send(p.ca, b"after").unwrap();
        assert_eq!(finish(&hca, &mut p, &mut buf), Some(RcEvent::Failed(RcFailure::RemoteAccess)), "case {which}");
        assert_eq!(p.a.rc_poll(p.ca, &mut buf), Some(RcEvent::Failed(RcFailure::Flushed)), "case {which}");
        assert_eq!(p.a.rc_state(p.ca), Some(RcState::Failed));
        assert_eq!(hca.qp_state(p.ia.qpn), 6);
        let mut seen = [0u8; 64];
        p.b.rc_window_read(p.cb, WINDOW_LEN - 64, &mut seen).unwrap();
        assert_eq!(seen, canary, "case {which}: nothing was written");
    }
}

#[test]
fn a_revoked_window_stays_revoked() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut p = pair(&mlx, &hca);
    let mut buf = [0u8; 64];
    let first = p.ib.window;
    let live = dma.live.get();

    p.b.rc_destroy(p.cb);
    assert!(dma.live.get() < live, "the window and the queues are freed");
    assert!(!hca.state.borrow().fw.mrs.contains_key(&18), "taken back from the adapter");
    // The peer is gone: a write finds nobody.
    p.a.rc_write(p.ca, first.addr, first.rkey, b"late").unwrap();
    assert_eq!(finish(&hca, &mut p, &mut buf), Some(RcEvent::Failed(RcFailure::RetryExceeded)));

    // A new connection in the same slot has a window and a key of its own.
    let (cb2, second) = p.b.rc_create().unwrap();
    assert_eq!(hca.state.borrow().fw.mrs[&18].key.rotate_left(8), second.window.rkey);
    assert_ne!(second.window.rkey, first.rkey, "the old key means nothing now");
    let _ = cb2;
}

#[test]
fn failures_in_the_adapter_are_reported_and_unwound() {
    for opcode in [op::SW2HW_CQ, op::SW2HW_MPT, op::RST2INIT_QP] {
        let hca = FakeHca::new(IB);
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        let mut ib = mlx.open_ib(1, QKEY).unwrap();
        let (qps, mrs, live) = (hca.qps(), hca.state.borrow().fw.mrs.len(), dma.live.get());
        {
            let mut s = hca.state.borrow_mut();
            s.fail = Some((opcode, 0x10));
        }
        assert_eq!(ib.rc_create().err(), Some(Mlx4Error::Command { opcode, status: 0x10 }));
        hca.state.borrow_mut().fail = None;
        assert_eq!((hca.qps(), hca.state.borrow().fw.mrs.len(), dma.live.get()), (qps, mrs, live), "{opcode:#x}");
        ib.rc_create().unwrap();
    }

    // The connection transitions failing leaves it failed, not half-made.
    for opcode in [op::INIT2RTR_QP, op::RTR2RTS_QP] {
        let hca = FakeHca::new(IB);
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        let mut ib = mlx.open_ib(1, QKEY).unwrap();
        let (id, _) = ib.rc_create().unwrap();
        hca.state.borrow_mut().fail = Some((opcode, 0x10));
        assert_eq!(ib.rc_connect(id, &params(8, 75, 0, 0)), Err(Mlx4Error::Command { opcode, status: 0x10 }));
        assert_eq!(ib.rc_state(id), Some(RcState::Failed));
        hca.state.borrow_mut().fail = None;
        assert_eq!(ib.rc_connect(id, &params(8, 75, 0, 0)), Err(Mlx4Error::BadParameter));
        ib.rc_destroy(id);
        assert_eq!(hca.qps().len(), 3);
    }
}

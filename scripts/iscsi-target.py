#!/usr/bin/env python3
"""A minimal iSCSI target (RFC 7143) serving one raw image as LUN 0.

Standard library only. One connection at a time, error recovery level 0,
no authentication and no digests. The target is named
iqn.2026-10.org.osmium:disk0.

By default it speaks iSCSI on stdin/stdout, which suits QEMU's user-mode
network forwarding, launched once per connection:

    -netdev user,id=n0,guestfwd=tcp:10.0.2.100:3260-cmd:python3 scripts/iscsi-target.py disk.img

Logs go to stderr (or --log FILE), and nowhere when stderr is the TCP stream
as well, which is how QEMU's guestfwd launches commands. For manual
testing it can listen on a port instead (and serves connections one after another):

    python3 scripts/iscsi-target.py --listen 3260 disk.img
    qemu-img info iscsi://127.0.0.1:3260/iqn.2026-10.org.osmium:disk0/0

    python3 scripts/iscsi-target.py --self-test

runs a small Python initiator against it.

Supported: login (SecurityNegotiation with AuthMethod=None, operational
negotiation, either stage skipped), NOP-Out, Text (SendTargets), Logout,
Task Management (answered as complete), and the SCSI commands INQUIRY
(standard and VPD pages 0x00, 0x80, 0x83), TEST UNIT READY, REQUEST SENSE,
READ CAPACITY(10)/(16), READ(6/10/16), WRITE(6/10/16), SYNCHRONIZE CACHE
(10/16), MODE SENSE(6/10), REPORT LUNS. Writes take immediate data and
unsolicited Data-Out as negotiated and ask for the rest with R2Ts.
"""

import argparse
import os
import socket
import struct
import sys
import tempfile
import threading

TARGET_NAME = "iqn.2026-10.org.osmium:disk0"
BLOCK = 512
RESERVED = 0xFFFFFFFF

# Opcodes.
NOP_OUT, SCSI_CMD, TASK_MGMT, LOGIN_REQ, TEXT_REQ, DATA_OUT, LOGOUT_REQ = 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
NOP_IN, SCSI_RESP, TASK_MGMT_RESP, LOGIN_RESP, TEXT_RESP, DATA_IN, LOGOUT_RESP = 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26
R2T, REJECT = 0x31, 0x3F

GOOD, CHECK_CONDITION = 0x00, 0x02
NOT_READY, MEDIUM_ERROR, ILLEGAL_REQUEST, UNIT_ATTENTION, DATA_PROTECT = 0x2, 0x3, 0x5, 0x6, 0x7

# What the target wants; the results follow each key's function.
TARGET_KEYS = {
    "MaxRecvDataSegmentLength": 65536,
    "MaxBurstLength": 262144,
    "FirstBurstLength": 65536,
    "InitialR2T": "No",
    "ImmediateData": "Yes",
    "MaxOutstandingR2T": 1,
    "MaxConnections": 1,
    "ErrorRecoveryLevel": 0,
    "DefaultTime2Wait": 2,
    "DefaultTime2Retain": 0,
    "DataPDUInOrder": "Yes",
    "DataSequenceInOrder": "Yes",
}
MIN_KEYS = {"MaxBurstLength", "FirstBurstLength", "MaxOutstandingR2T", "MaxConnections", "ErrorRecoveryLevel",
            "DefaultTime2Retain"}
MAX_KEYS = {"DefaultTime2Wait"}
OR_KEYS = {"InitialR2T", "DataPDUInOrder", "DataSequenceInOrder"}
AND_KEYS = {"ImmediateData"}


LOG = sys.stderr


def log(*args):
    print("[iscsi-target]", *args, file=LOG, flush=True)


def parse_text(data):
    """key=value pairs from a data segment, in order."""
    pairs = []
    for item in data.split(b"\0"):
        if item:
            k, _, v = item.decode("utf-8", "replace").partition("=")
            pairs.append((k, v))
    return pairs


def make_text(pairs):
    return b"".join(f"{k}={v}".encode() + b"\0" for k, v in pairs)


def number(v):
    return int(v, 16) if v.lower().startswith("0x") else int(v)


def u32(b, off):
    return struct.unpack_from(">I", b, off)[0]


class Pdu:
    """A raw PDU: the 48-byte BHS and the data segment."""

    def __init__(self, bhs=None, data=b""):
        self.bhs = bytearray(bhs if bhs is not None else 48)
        self.data = bytes(data)

    @property
    def opcode(self):
        return self.bhs[0] & 0x3F

    @property
    def immediate(self):
        return bool(self.bhs[0] & 0x40)

    @property
    def flags(self):
        return self.bhs[1]

    def get(self, off):
        return u32(self.bhs, off)

    def set(self, off, v):
        struct.pack_into(">I", self.bhs, off, v & 0xFFFFFFFF)

    def encode(self):
        bhs = bytearray(self.bhs)
        bhs[4] = 0
        bhs[5:8] = len(self.data).to_bytes(3, "big")
        pad = -len(self.data) % 4
        return bytes(bhs) + self.data + b"\0" * pad


def read_pdu(read_exact):
    """The next PDU from the stream, or None at end of stream."""
    bhs = read_exact(48)
    if bhs is None:
        return None
    ahs = bhs[4] * 4
    dlen = int.from_bytes(bhs[5:8], "big")
    rest = read_exact(ahs + dlen + (-dlen % 4))
    if rest is None:
        return None
    return Pdu(bhs, rest[ahs:ahs + dlen])


class Stream:
    """Reads and writes PDUs over a pair of binary file objects."""

    def __init__(self, rfile, wfile):
        self.rfile, self.wfile = rfile, wfile

    def read_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.rfile.read(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    def recv(self):
        return read_pdu(self.read_exact)

    def send(self, pdu):
        self.wfile.write(pdu.encode())
        self.wfile.flush()


class Disk:
    def __init__(self, path, read_only):
        self.read_only = read_only or not os.access(path, os.W_OK)
        self.f = open(path, "rb" if self.read_only else "r+b")
        self.f.seek(0, os.SEEK_END)
        self.blocks = self.f.tell() // BLOCK

    def read(self, lba, n):
        self.f.seek(lba * BLOCK)
        return self.f.read(n * BLOCK)

    def write(self, lba, data):
        self.f.seek(lba * BLOCK)
        self.f.write(data)

    def flush(self):
        if not self.read_only:
            self.f.flush()
            os.fsync(self.f.fileno())


class CheckCondition(Exception):
    def __init__(self, key, asc, ascq=0):
        super().__init__(f"sense {key:#x}/{asc:#04x}/{ascq:#04x}")
        self.key, self.asc, self.ascq = key, asc, ascq

    def sense(self):
        s = bytearray(18)
        s[0], s[2], s[7], s[12], s[13] = 0x70, self.key, 10, self.asc, self.ascq
        return bytes(s)


class Session:
    """One connection: login, then full feature phase until logout."""

    def __init__(self, stream, disk, address):
        self.s = stream
        self.disk = disk
        self.address = address
        self.stat_sn = 0
        self.exp_cmd_sn = 0
        self.full_feature = False
        self.discovery = False
        self.params = {k: v for k, v in TARGET_KEYS.items()}
        # Until the initiator declares it, the login default.
        self.initiator_mrdsl = 8192
        self.unit_attention = True
        self.ttt = 0x10
        self.declared = False

    # Sequence numbers.

    def window(self, pdu):
        pdu.set(28, self.exp_cmd_sn)
        pdu.set(32, self.exp_cmd_sn + 31)

    def status_sn(self, pdu):
        pdu.set(24, self.stat_sn)
        self.stat_sn = (self.stat_sn + 1) & 0xFFFFFFFF
        self.window(pdu)

    def command_sn(self, req):
        if not req.immediate:
            self.exp_cmd_sn = (req.get(24) + 1) & 0xFFFFFFFF

    # Login.

    def negotiate(self, key, value, out):
        if key in ("InitiatorName", "InitiatorAlias", "TargetName", "SessionType"):
            return True
        if key == "AuthMethod":
            if "None" not in value.split(","):
                return False
            out.append((key, "None"))
        elif key in ("HeaderDigest", "DataDigest"):
            out.append((key, "None" if "None" in value.split(",") else "Reject"))
        elif key == "MaxRecvDataSegmentLength":
            self.initiator_mrdsl = number(value)
        elif key in MIN_KEYS:
            self.params[key] = min(number(value), TARGET_KEYS[key])
            out.append((key, self.params[key]))
        elif key in MAX_KEYS:
            self.params[key] = max(number(value), TARGET_KEYS[key])
            out.append((key, self.params[key]))
        elif key in OR_KEYS:
            self.params[key] = "Yes" if "Yes" in (value, TARGET_KEYS[key]) else "No"
            out.append((key, self.params[key]))
        elif key in AND_KEYS:
            self.params[key] = "Yes" if value == TARGET_KEYS[key] == "Yes" else "No"
            out.append((key, self.params[key]))
        elif key in ("IFMarker", "OFMarker"):
            out.append((key, "No"))
        else:
            out.append((key, "NotUnderstood"))
        return True

    def login(self, req):
        flags = req.flags
        transit, csg, nsg = bool(flags & 0x80), (flags >> 2) & 3, flags & 3
        keys = parse_text(req.data)
        names = dict(keys)
        if self.stat_sn == 0:
            self.exp_cmd_sn = req.get(24)
            self.stat_sn = req.get(28) or 1
        resp = Pdu()
        resp.bhs[0] = LOGIN_RESP
        resp.bhs[8:16] = req.bhs[8:16]  # ISID, TSIH
        resp.set(16, req.get(16))
        status = (0, 0)
        if "SessionType" in names:
            self.discovery = names["SessionType"] == "Discovery"
        if "InitiatorName" in names:
            log(f"login from {names['InitiatorName']} ({'discovery' if self.discovery else 'normal'})")
        if not self.discovery and "TargetName" in names and names["TargetName"] != TARGET_NAME:
            log(f"no target {names['TargetName']}")
            status = (2, 3)
        out = []
        if status == (0, 0) and not all(self.negotiate(k, v, out) for k, v in keys):
            status = (2, 1)  # authentication failure
        self.params["FirstBurstLength"] = min(self.params["FirstBurstLength"], self.params["MaxBurstLength"])
        if "InitiatorName" in names:
            out.append(("TargetPortalGroupTag", 1))
        if csg == 1 and not self.declared:
            # Declared once, in operational negotiation.
            out.append(("MaxRecvDataSegmentLength", TARGET_KEYS["MaxRecvDataSegmentLength"]))
            self.declared = True
        resp.bhs[36], resp.bhs[37] = status
        if status == (0, 0):
            resp.bhs[1] = (0x80 if transit else 0) | csg << 2 | (nsg if transit else 0)
            if transit and nsg == 3:
                resp.bhs[14:16] = (1).to_bytes(2, "big")
                self.full_feature = True
                log(f"full feature phase: {self.params}, initiator MRDSL {self.initiator_mrdsl}")
            resp.data = make_text(out)
        else:
            resp.bhs[1] = csg << 2
        self.status_sn(resp)
        self.s.send(resp)
        return status == (0, 0)

    # Full feature phase.

    def nop(self, req):
        if req.get(16) == RESERVED:
            return  # an answer to a ping of ours; we send none
        resp = Pdu()
        resp.bhs[0], resp.bhs[1] = NOP_IN, 0x80
        resp.bhs[8:16] = req.bhs[8:16]
        resp.set(16, req.get(16))
        resp.set(20, RESERVED)
        resp.data = req.data
        self.status_sn(resp)
        self.s.send(resp)

    def text(self, req):
        pairs = parse_text(req.data)
        out = []
        for k, v in pairs:
            if k == "SendTargets":
                if v in ("All", TARGET_NAME) or (v == "" and not self.discovery):
                    out += [("TargetName", TARGET_NAME), ("TargetAddress", self.address)]
            else:
                out.append((k, "NotUnderstood"))
        resp = Pdu()
        resp.bhs[0], resp.bhs[1] = TEXT_RESP, 0x80
        resp.set(16, req.get(16))
        resp.set(20, RESERVED)
        resp.data = make_text(out)
        self.status_sn(resp)
        self.s.send(resp)

    def logout(self, req):
        resp = Pdu()
        resp.bhs[0], resp.bhs[1] = LOGOUT_RESP, 0x80
        resp.set(16, req.get(16))
        self.status_sn(resp)
        self.s.send(resp)
        log("logout")

    def task_mgmt(self, req):
        resp = Pdu()
        resp.bhs[0], resp.bhs[1], resp.bhs[2] = TASK_MGMT_RESP, 0x80, 0  # function complete
        resp.set(16, req.get(16))
        self.status_sn(resp)
        self.s.send(resp)

    def reject(self, req, reason):
        resp = Pdu()
        resp.bhs[0], resp.bhs[1], resp.bhs[2] = REJECT, 0x80, reason
        resp.set(16, RESERVED)
        resp.data = bytes(req.bhs)
        self.status_sn(resp)
        self.s.send(resp)

    def response(self, itt, status, sense=b"", residual=0, underflow=False):
        resp = Pdu()
        resp.bhs[0], resp.bhs[1], resp.bhs[2], resp.bhs[3] = SCSI_RESP, 0x80 | (0x02 if underflow else 0), 0, status
        resp.set(16, itt)
        resp.set(44, residual)
        if sense:
            resp.data = len(sense).to_bytes(2, "big") + sense
        self.status_sn(resp)
        self.s.send(resp)

    def data_in(self, req, data):
        """Sends `data` in Data-In PDUs, the status in the last one."""
        itt, expected = req.get(16), req.get(20)
        data = data[:expected]
        residual = expected - len(data)
        seg = max(512, self.initiator_mrdsl)
        burst = self.params["MaxBurstLength"]
        offset, data_sn = 0, 0
        while True:
            chunk = data[offset:offset + seg]
            # Keep each sequence within MaxBurstLength: F at its end.
            seq_end = (offset // burst + 1) * burst
            chunk = chunk[:seq_end - offset]
            last = offset + len(chunk) >= len(data)
            pdu = Pdu()
            pdu.bhs[0] = DATA_IN
            pdu.bhs[1] = 0x80 if last or offset + len(chunk) == seq_end else 0
            pdu.bhs[8:16] = req.bhs[8:16]
            pdu.set(16, itt)
            pdu.set(20, RESERVED)
            pdu.set(36, data_sn)
            pdu.set(40, offset)
            pdu.data = chunk
            if last:
                pdu.bhs[1] |= 0x01 | (0x02 if residual else 0)
                pdu.bhs[3] = GOOD
                pdu.set(44, residual)
                self.status_sn(pdu)
            else:
                self.window(pdu)
            self.s.send(pdu)
            offset += len(chunk)
            data_sn += 1
            if last:
                return

    def receive_write(self, req, length):
        """Collects a write's data: immediate, unsolicited, then by R2T.
        Returns the data, or None if the connection ended."""
        itt = req.get(16)
        buf = bytearray(length)
        got = len(req.data)
        buf[:got] = req.data[:length]
        final = bool(req.flags & 0x80)
        first_burst = min(self.params["FirstBurstLength"], length)
        # Unsolicited Data-Out until the F bit, when the command did not have it.
        while not final:
            pdu = self.s.recv()
            if pdu is None:
                return None
            if pdu.opcode == NOP_OUT:
                self.command_sn(pdu)
                self.nop(pdu)
                continue
            if pdu.opcode != DATA_OUT or pdu.get(16) != itt:
                raise ProtocolError(f"expected unsolicited Data-Out, got opcode {pdu.opcode:#x}")
            off = pdu.get(40)
            buf[off:off + len(pdu.data)] = pdu.data
            got = max(got, off + len(pdu.data))
            final = bool(pdu.flags & 0x80)
        if got > first_burst and got > len(req.data):
            log(f"warning: {got} bytes unsolicited, FirstBurstLength {first_burst}")
        r2t_sn = 0
        while got < length:
            want = min(self.params["MaxBurstLength"], length - got)
            ttt = self.ttt
            self.ttt = (self.ttt + 1) & 0x7FFFFFFF
            r2t = Pdu()
            r2t.bhs[0], r2t.bhs[1] = R2T, 0x80
            r2t.bhs[8:16] = req.bhs[8:16]
            r2t.set(16, itt)
            r2t.set(20, ttt)
            r2t.set(24, self.stat_sn)
            self.window(r2t)
            r2t.set(36, r2t_sn)
            r2t.set(40, got)
            r2t.set(44, want)
            self.s.send(r2t)
            r2t_sn += 1
            end = got + want
            while True:
                pdu = self.s.recv()
                if pdu is None:
                    return None
                if pdu.opcode == NOP_OUT:
                    self.command_sn(pdu)
                    self.nop(pdu)
                    continue
                if pdu.opcode != DATA_OUT or pdu.get(16) != itt or pdu.get(20) != ttt:
                    raise ProtocolError(f"expected Data-Out for R2T {ttt:#x}")
                off = pdu.get(40)
                if off + len(pdu.data) > end:
                    raise ProtocolError("Data-Out beyond the R2T")
                buf[off:off + len(pdu.data)] = pdu.data
                if pdu.flags & 0x80:
                    break
            got = end
        return bytes(buf)

    def drain_unsolicited(self, itt):
        """Swallows a failed write's unsolicited Data-Out, up to its F bit."""
        while True:
            pdu = self.s.recv()
            if pdu is None or (pdu.opcode == DATA_OUT and pdu.get(16) == itt and pdu.flags & 0x80):
                return
            if pdu.opcode != DATA_OUT:
                raise ProtocolError(f"expected unsolicited Data-Out, got opcode {pdu.opcode:#x}")

    def scsi(self, req):
        itt, lun = req.get(16), req.bhs[8:16]
        cdb = bytes(req.bhs[32:48])
        opc = cdb[0]
        write = bool(req.flags & 0x20)
        try:
            if lun[:2] != b"\0\0" and opc not in (0x12, 0xA0, 0x03):
                raise CheckCondition(ILLEGAL_REQUEST, 0x25)  # LOGICAL UNIT NOT SUPPORTED
            if self.unit_attention and opc not in (0x12, 0xA0, 0x03):
                self.unit_attention = False
                raise CheckCondition(UNIT_ATTENTION, 0x29)  # POWER ON OR RESET
            if write:
                return self.scsi_write(req, cdb)
            data = self.scsi_in(cdb, lun)
            if data is None:
                self.response(itt, GOOD)
            else:
                self.data_in(req, data)
        except CheckCondition as e:
            log(f"command {opc:#04x}: {e}")
            if write and not req.flags & 0x80:
                self.drain_unsolicited(itt)
            self.response(itt, CHECK_CONDITION, e.sense())

    def lba_range(self, cdb):
        opc = cdb[0]
        if opc in (0x08, 0x0A):
            lba = int.from_bytes(cdb[1:4], "big") & 0x1FFFFF
            n = cdb[4] or 256
        elif opc in (0x28, 0x2A):
            lba, n = u32(cdb, 2), int.from_bytes(cdb[7:9], "big")
        else:
            lba, n = int.from_bytes(cdb[2:10], "big"), u32(cdb, 10)
        if lba + n > self.disk.blocks:
            raise CheckCondition(ILLEGAL_REQUEST, 0x21)
        return lba, n

    def scsi_write(self, req, cdb):
        itt = req.get(16)
        if cdb[0] not in (0x0A, 0x2A, 0x8A):
            raise CheckCondition(ILLEGAL_REQUEST, 0x20)
        lba, n = self.lba_range(cdb)
        if self.disk.read_only:
            raise CheckCondition(DATA_PROTECT, 0x27)
        if req.get(20) != n * BLOCK:
            raise CheckCondition(ILLEGAL_REQUEST, 0x24)
        data = self.receive_write(req, n * BLOCK)
        if data is None:
            return
        self.disk.write(lba, data)
        self.response(itt, GOOD)

    def scsi_in(self, cdb, lun):
        """Data for a command without output, or None for status only."""
        opc = cdb[0]
        if opc == 0x00:  # TEST UNIT READY
            return None
        if opc == 0x03:  # REQUEST SENSE: nothing pending
            return CheckCondition(0, 0).sense()
        if opc == 0x12:  # INQUIRY
            alloc = int.from_bytes(cdb[3:5], "big")
            if cdb[1] & 1:
                return self.vpd(cdb[2])[:alloc]
            if cdb[2]:
                raise CheckCondition(ILLEGAL_REQUEST, 0x24)
            d = bytearray(b" " * 36)
            d[0:8] = bytes([0x00 if lun[:2] == b"\0\0" else 0x7F, 0, 6, 2, 31, 0, 0, 0x02])
            d[8:16] = b"OSMIUM  "
            d[16:32] = b"iscsi-target.py "
            d[32:36] = b"0001"
            return bytes(d[:alloc])
        if opc == 0x25:  # READ CAPACITY(10)
            last = min(self.disk.blocks - 1, 0xFFFFFFFF)
            return struct.pack(">II", last, BLOCK)
        if opc == 0x9E and cdb[1] & 0x1F == 0x10:  # READ CAPACITY(16)
            alloc = u32(cdb, 10)
            return struct.pack(">QI", self.disk.blocks - 1, BLOCK).ljust(32, b"\0")[:alloc]
        if opc in (0x08, 0x28, 0x88):  # READ
            lba, n = self.lba_range(cdb)
            return self.disk.read(lba, n)
        if opc in (0x35, 0x91):  # SYNCHRONIZE CACHE
            self.disk.flush()
            return None
        if opc in (0x1A, 0x5A):  # MODE SENSE(6)/(10): no pages, WP bit
            wp = 0x80 if self.disk.read_only else 0
            if opc == 0x1A:
                return bytes([3, 0, wp, 0])[:cdb[4]]
            return bytes([0, 6, 0, wp, 0, 0, 0, 0])[:int.from_bytes(cdb[7:9], "big")]
        if opc == 0xA0:  # REPORT LUNS: just LUN 0
            return (struct.pack(">II", 8, 0) + bytes(8))[:u32(cdb, 6)]
        raise CheckCondition(ILLEGAL_REQUEST, 0x20)  # INVALID COMMAND OPERATION CODE

    def vpd(self, page):
        if page == 0x00:
            body = bytes([0x00, 0x80, 0x83])
        elif page == 0x80:
            body = b"osmium0001"
        elif page == 0x83:
            name = TARGET_NAME.encode() + b",L,0x0000"
            name += b"\0" * (-len(name) % 4 or 4)
            body = bytes([0x53, 0x08, 0, len(name)]) + name  # SCSI name string, UTF-8
        else:
            raise CheckCondition(ILLEGAL_REQUEST, 0x24)
        return bytes([0, page]) + len(body).to_bytes(2, "big") + body

    def run(self):
        while True:
            req = self.s.recv()
            if req is None:
                log("connection closed")
                return
            op = req.opcode
            if not self.full_feature:
                if op != LOGIN_REQ:
                    log(f"opcode {op:#x} before login")
                    return
                if not self.login(req):
                    return
                continue
            if op in (NOP_OUT, SCSI_CMD, TEXT_REQ, LOGOUT_REQ, TASK_MGMT):
                self.command_sn(req)
            if op == NOP_OUT:
                self.nop(req)
            elif op == SCSI_CMD:
                if self.discovery:
                    self.reject(req, 0x05)  # command not supported in discovery
                else:
                    self.scsi(req)
            elif op == TEXT_REQ:
                self.text(req)
            elif op == LOGOUT_REQ:
                self.logout(req)
                return
            elif op == TASK_MGMT:
                self.task_mgmt(req)
            elif op == DATA_OUT:
                log("stray Data-Out")
            else:
                self.reject(req, 0x04)  # protocol error


class ProtocolError(Exception):
    pass


def serve(stream, disk, address):
    try:
        Session(stream, disk, address).run()
    except ProtocolError as e:
        log(f"protocol error: {e}")
    except (BrokenPipeError, ConnectionResetError) as e:
        log(f"connection lost: {e}")


def listen(port, disk, address):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    log(f"listening on port {srv.getsockname()[1]}, {disk.blocks} blocks")
    while True:
        conn, peer = srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        log(f"connection from {peer[0]}:{peer[1]}")
        here = address or f"{conn.getsockname()[0]}:{conn.getsockname()[1]},1"
        with conn, conn.makefile("rb") as r, conn.makefile("wb") as w:
            serve(Stream(r, w), disk, here)


# A minimal initiator, for --self-test.

class Initiator:
    def __init__(self, sock):
        self.r = sock.makefile("rb")
        self.w = sock.makefile("wb")
        self.s = Stream(self.r, self.w)
        self.cmd_sn, self.exp_stat_sn, self.itt = 1, 0, 0
        self.params = {}

    def next_itt(self):
        self.itt += 1
        return self.itt

    def recv(self):
        pdu = self.s.recv()
        assert pdu is not None, "connection closed"
        if pdu.opcode in (SCSI_RESP, LOGIN_RESP, TEXT_RESP, LOGOUT_RESP, NOP_IN) or (
                pdu.opcode == DATA_IN and pdu.flags & 1):
            self.exp_stat_sn = pdu.get(24) + 1
        return pdu

    def login(self, keys, target=TARGET_NAME, discovery=False):
        itt = self.next_itt()
        sec = [("InitiatorName", "iqn.2026-10.org.osmium:selftest"),
               ("SessionType", "Discovery" if discovery else "Normal")]
        if not discovery:
            sec.append(("TargetName", target))
        sec.append(("AuthMethod", "None"))
        for csg, nsg, pairs in ((0, 1, sec), (1, 3, keys)):
            req = Pdu()
            req.bhs[0], req.bhs[1] = LOGIN_REQ | 0x40, 0x80 | csg << 2 | nsg
            req.bhs[8:14] = bytes([0x80, 0, 0, 0, 0, 1])
            req.set(16, itt)
            req.set(24, self.cmd_sn)
            req.set(28, self.exp_stat_sn)
            req.data = make_text(pairs)
            self.s.send(req)
            resp = self.recv()
            assert resp.opcode == LOGIN_RESP
            if resp.bhs[36]:
                return resp.bhs[36], resp.bhs[37]
            self.params.update(parse_text(resp.data))
        assert resp.flags & 0x83 == 0x83, "in full feature phase"
        return 0, 0

    def command(self, cdb, read_len=0, out=b""):
        itt = self.next_itt()
        p = self.params
        imm = b""
        if out and p.get("ImmediateData") == "Yes":
            imm = out[:min(int(p["FirstBurstLength"]), int(p["MaxRecvDataSegmentLength"]))]
        unsol = 0
        if out and p.get("InitialR2T") == "No":
            unsol = min(int(p["FirstBurstLength"]), len(out))
        req = Pdu()
        req.bhs[0] = SCSI_CMD
        req.bhs[1] = (0x80 if unsol <= len(imm) else 0) | (0x40 if read_len else 0) | (0x20 if out else 0) | 1
        req.set(16, itt)
        req.set(20, read_len or len(out))
        req.set(24, self.cmd_sn)
        req.set(28, self.exp_stat_sn)
        req.bhs[32:32 + len(cdb)] = cdb
        req.data = imm
        self.cmd_sn += 1
        self.s.send(req)
        seg = int(p.get("MaxRecvDataSegmentLength", 8192))

        def data_out(start, end, ttt):
            for i, off in enumerate(range(start, end, seg)):
                d = Pdu()
                d.bhs[0], d.bhs[1] = DATA_OUT, 0x80 if off + seg >= end else 0
                d.set(16, itt)
                d.set(20, ttt)
                d.set(28, self.exp_stat_sn)
                d.set(36, i)
                d.set(40, off)
                d.data = out[off:min(end, off + seg)]
                self.s.send(d)

        if unsol > len(imm):
            data_out(len(imm), unsol, RESERVED)
        data = bytearray(read_len)
        r2ts = 0
        while True:
            pdu = self.recv()
            if pdu.opcode == DATA_IN:
                off = pdu.get(40)
                data[off:off + len(pdu.data)] = pdu.data
                if pdu.flags & 1:
                    return pdu.bhs[3], bytes(data), r2ts
            elif pdu.opcode == R2T:
                r2ts += 1
                data_out(pdu.get(40), pdu.get(40) + pdu.get(44), pdu.get(20))
            elif pdu.opcode == SCSI_RESP:
                sense = pdu.data[2:]
                return pdu.bhs[3], sense if pdu.bhs[3] else bytes(data), r2ts
            else:
                raise AssertionError(f"unexpected opcode {pdu.opcode:#x}")

    def simple(self, opcode, data=b""):
        req = Pdu()
        req.bhs[0], req.bhs[1] = opcode | 0x40, 0x80
        req.set(16, self.next_itt())
        req.set(20, RESERVED)
        req.set(24, self.cmd_sn)
        req.set(28, self.exp_stat_sn)
        req.data = data
        self.s.send(req)
        return self.recv()


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "disk.img")
        blocks = 4096
        with open(path, "wb") as f:
            f.write(bytes(i % 251 for i in range(blocks * BLOCK)))
        disk = Disk(path, False)

        def session(fn):
            a, b = socket.socketpair()
            t = threading.Thread(target=lambda: serve(Stream(b.makefile("rb"), b.makefile("wb")), disk,
                                                      "127.0.0.1:3260,1"))
            t.start()
            try:
                fn(Initiator(a))
            finally:
                a.close()
                t.join(5)
                b.close()

        def discovery(i):
            assert i.login([("HeaderDigest", "None"), ("DataDigest", "None")], discovery=True) == (0, 0)
            resp = i.simple(TEXT_REQ, make_text([("SendTargets", "All")]))
            assert resp.opcode == TEXT_RESP
            assert parse_text(resp.data) == [("TargetName", TARGET_NAME), ("TargetAddress", "127.0.0.1:3260,1")]
            assert i.simple(LOGOUT_REQ).opcode == LOGOUT_RESP

        def refused(i):
            assert i.login([], target="iqn.nonesuch") == (2, 3)

        def io(keys, expect_r2ts):
            def run(i):
                assert i.login(keys) == (0, 0)
                status, sense, _ = i.command(bytes([0x00, 0, 0, 0, 0, 0]))
                assert status == CHECK_CONDITION and sense[2] == UNIT_ATTENTION
                assert i.command(bytes(6))[0] == GOOD
                status, inq, _ = i.command(bytes([0x12, 0, 0, 0, 36, 0]), read_len=36)
                assert status == GOOD and inq[8:14] == b"OSMIUM"
                status, cap, _ = i.command(bytes([0x25]) + bytes(9), read_len=8)
                assert struct.unpack(">II", cap) == (blocks - 1, BLOCK)
                status, cap, _ = i.command(bytes([0x9E, 0x10]) + bytes(8) + (32).to_bytes(4, "big") + bytes(2),
                                           read_len=32)
                assert struct.unpack(">QI", cap[:12]) == (blocks - 1, BLOCK)
                payload = bytes((i * 7 + 3) % 256 for i in range(256 * BLOCK))
                status, _, r2ts = i.command(bytes([0x2A, 0, 0, 0, 0, 10, 0, 1, 0, 0]), out=payload)
                assert status == GOOD and r2ts == expect_r2ts, (status, r2ts)
                status, back, _ = i.command(bytes([0x88, 0]) + (10).to_bytes(8, "big") + (256).to_bytes(4, "big")
                                            + bytes(2), read_len=len(payload))
                assert status == GOOD and back == payload
                assert i.command(bytes([0x35]) + bytes(9))[0] == GOOD
                status, sense, _ = i.command(bytes([0x28, 0]) + blocks.to_bytes(4, "big") + bytes([0, 0, 1, 0]),
                                             read_len=BLOCK)
                assert status == CHECK_CONDITION and sense[2] == ILLEGAL_REQUEST and sense[12] == 0x21
                status, luns, _ = i.command(bytes([0xA0]) + bytes(5) + (16).to_bytes(4, "big") + bytes(2),
                                            read_len=16)
                assert luns == struct.pack(">II", 8, 0) + bytes(8)
                pong = i.simple(NOP_OUT, b"ping")
                assert pong.opcode == NOP_IN and pong.data == b"ping"
                assert i.simple(LOGOUT_REQ).opcode == LOGOUT_RESP
            return run

        session(discovery)
        session(refused)
        # Unsolicited data up to FirstBurstLength, the rest by R2T.
        session(io([("InitialR2T", "No"), ("ImmediateData", "Yes"), ("MaxRecvDataSegmentLength", "8192"),
                    ("FirstBurstLength", "65536"), ("MaxBurstLength", "65536")], 1))
        # Everything by R2T, in MaxBurstLength pieces.
        session(io([("InitialR2T", "Yes"), ("ImmediateData", "No"), ("MaxRecvDataSegmentLength", "512"),
                    ("MaxBurstLength", "16384")], 8))
        with open(path, "rb") as f:
            f.seek(10 * BLOCK)
            assert f.read(BLOCK)[:4] == bytes([3, 10, 17, 24])
    print("iscsi-target self-test passed", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="A minimal single-LUN iSCSI target.")
    ap.add_argument("image", nargs="?", help="raw disk image to serve as LUN 0")
    ap.add_argument("--listen", type=int, metavar="PORT", help="listen on a TCP port instead of stdin/stdout")
    ap.add_argument("--address", help="TargetAddress for SendTargets (default: the connection's own)")
    ap.add_argument("--read-only", action="store_true", help="refuse writes")
    ap.add_argument("--self-test", action="store_true", help="test against a built-in initiator and exit")
    ap.add_argument("--log", metavar="FILE", help="append logs to FILE instead of stderr")
    args = ap.parse_args()
    global LOG
    if args.log:
        LOG = open(args.log, "a")
    elif args.listen is None and not args.self_test and os.path.sameopenfile(1, 2):
        # QEMU's guestfwd hands the connection over as stderr too, where a
        # log line would corrupt the stream.
        LOG = open(os.devnull, "w")
    if args.self_test:
        self_test()
        return
    if not args.image:
        ap.error("an image is required")
    disk = Disk(args.image, args.read_only)
    if args.listen is not None:
        listen(args.listen, disk, args.address)
    else:
        log(f"serving {args.image} ({disk.blocks} blocks) on stdin/stdout")
        serve(Stream(sys.stdin.buffer, sys.stdout.buffer), disk, args.address or "10.0.2.100:3260,1")


if __name__ == "__main__":
    main()

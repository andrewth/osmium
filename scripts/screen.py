#!/usr/bin/env python3
"""Checks what a QEMU guest put on its screen.

Connects to QEMU's QMP socket and takes screendumps until the picture is
WIDTHxHEIGHT (any size if both are 0) and shows the eight colour bars of
examples/demos/src/display.rs, or fails after TIMEOUT seconds or when QEMU
exits. DEVICE picks a display by its qdev id when there are several.

    screen.py QMP_SOCKET WIDTH HEIGHT [TIMEOUT] [DEVICE]
"""
import json
import os
import socket
import sys
import tempfile
import time

BARS = [
    (0xff, 0xff, 0xff),
    (0xff, 0xff, 0x00),
    (0x00, 0xff, 0xff),
    (0x00, 0xff, 0x00),
    (0xff, 0x00, 0xff),
    (0xff, 0x00, 0x00),
    (0x00, 0x00, 0xff),
    (0x00, 0x00, 0x00),
]


def qmp(path, deadline):
    while True:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(path)
            break
        except OSError:
            if time.time() > deadline:
                raise
            time.sleep(0.1)
    f = s.makefile("rw")
    json.loads(f.readline())  # greeting

    def command(name, **args):
        f.write(json.dumps({"execute": name, "arguments": args}) + "\n")
        f.flush()
        while True:
            reply = json.loads(f.readline())
            if "return" in reply or "error" in reply:
                return reply

    command("qmp_capabilities")
    return s, command


def read_ppm(path):
    with open(path, "rb") as f:
        data = f.read()
    # P6, then width, height and maxval separated by whitespace.
    fields = data.split(maxsplit=4)
    if fields[0] != b"P6":
        raise ValueError("not a binary PPM")
    width, height, maxval = int(fields[1]), int(fields[2]), int(fields[3])
    pixels = data[len(data) - width * height * 3:]
    assert maxval == 255
    return width, height, pixels


def check(w, h, px, width, height):
    """Returns why the picture is wrong, or None."""
    if (width, height) != (0, 0) and (w, h) != (width, height):
        return f"{w}x{h}, expected {width}x{height}"
    bar = w // len(BARS)
    y = h // 2
    for i, want in enumerate(BARS):
        x = i * bar + bar // 2
        got = tuple(px[3 * (y * w + x):3 * (y * w + x) + 3])
        if got != want:
            return f"bar {i} at ({x}, {y}) is {got}, expected {want}"
    return None


def main():
    sock, width, height = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 60
    device = sys.argv[5] if len(sys.argv) > 5 else None
    deadline = time.time() + timeout
    s, command = qmp(sock, deadline)
    args = {"device": device} if device else {}
    problem = "no screendump"
    with tempfile.TemporaryDirectory() as d:
        dump = os.path.join(d, "screen.ppm")
        while time.time() < deadline:
            try:
                reply = command("screendump", filename=dump, **args)
            except (OSError, ValueError):
                s.close()
                sys.exit(f"screen: QEMU exited before the colour bars showed (last: {problem})")
            if "error" in reply:
                problem = reply["error"]["desc"]
            else:
                w, h, px = read_ppm(dump)
                problem = check(w, h, px, width, height)
                if problem is None:
                    print(f"screen: {w}x{h}, {len(BARS)} colour bars")
                    return
            time.sleep(0.5)
    s.close()
    sys.exit(f"screen: no colour bars after {timeout:.0f} s (last: {problem})")


if __name__ == "__main__":
    main()

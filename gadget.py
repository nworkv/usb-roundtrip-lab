#!/usr/bin/env python3
"""EP0-only full-speed descriptor emulator. No non-control endpoints."""
import argparse
import ctypes as C
import json
import os
from pathlib import Path
import struct
import time


def load_case(path):
    case = json.loads(Path(path).read_text())
    descriptors = {}
    for key, value in case['descriptors'].items():
        parts = tuple(int(x, 0) for x in key.split(':'))
        if len(parts) != 3:
            raise ValueError('Descriptor key must be type:index:language')
        descriptors[parts] = bytes.fromhex(value)
    device = descriptors.get((1, 0, 0), b'')
    if len(device) < 8 or device[7] != 64:
        raise ValueError('This version requires device descriptor bMaxPacketSize0=64')
    return case, descriptors


def response(setup, descriptors, configured):
    bm, req, value, index, length = struct.unpack('<BBHHH', setup)
    if bm == 0x80 and req == 6:
        data = descriptors.get((value >> 8, value & 255, index))
        return None if data is None else data[:length]
    if bm == 0x80 and req == 8 and value == 0 and index == 0:
        return bytes([configured])[:length]
    if bm in (0x80, 0x81) and req == 0 and value == 0:
        return b'\x00\x00'[:length]
    if bm == 0x81 and req == 10 and value == 0 and index == 0:
        return b'\x00'[:length]
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('case')
    ap.add_argument('--driver', required=True)
    ap.add_argument('--device', required=True)
    ap.add_argument('--log', required=True)
    args = ap.parse_args()
    case, descriptors = load_case(args.case)
    lib = C.CDLL(str(Path(__file__).resolve().with_name('libraw.so')))
    ptr = C.POINTER(C.c_ubyte)
    for name, types in {
        'rg_open': [C.c_char_p, C.c_char_p],
        'rg_event': [C.c_int, ptr],
        'rg_io': [C.c_int, C.c_int, ptr, C.c_uint, C.c_int],
        'rg_stall': [C.c_int], 'rg_configure': [C.c_int]
    }.items():
        getattr(lib, name).argtypes = types
        getattr(lib, name).restype = C.c_int
    def check(r):
        if r < 0:
            raise OSError(-r, os.strerror(-r))
        return r
    # Exclusive creation prevents accidentally mixing two runs.
    with open(args.log, 'x', buffering=1) as log:
        def emit(**row):
            row.update(case_id=case['id'], time_ns=time.time_ns())
            log.write(json.dumps(row) + '\n')
            log.flush()
            os.fsync(log.fileno())
        emit(event='start', case=case, driver=args.driver, device=args.device)
        fd = check(lib.rg_open(args.driver.encode(), args.device.encode()))
        configured = 0
        seq = 0
        try:
            while True:
                buf = (C.c_ubyte * 8)()
                event = check(lib.rg_event(fd, buf))
                if event != 2:
                    emit(event='udc_event', event_type=event)
                    if event in (5, 6):
                        configured = 0
                    continue
                setup = bytes(buf)
                bm, req, value, index, length = struct.unpack('<BBHHH', setup)
                seq += 1
                emit(event='setup', seq=seq, setup=setup.hex())
                data = response(setup, descriptors, configured)
                configure = bm == 0 and req == 9 and value == 1 and index == 0 and length == 0
                set_interface = bm == 1 and req == 11 and value == 0 and index == 0 and length == 0 and configured == 1
                if configure or set_interface:
                    if configure:
                        check(lib.rg_configure(fd))
                    data = b''
                if data is None:
                    r = lib.rg_stall(fd)
                    emit(event='stall', seq=seq, setup=setup.hex(), result=r)
                    check(r)
                    continue
                payload = (C.c_ubyte * max(1, len(data))).from_buffer_copy(data or b'\x00')
                emit(event='submit', seq=seq, setup=setup.hex(), data=data.hex())
                r = lib.rg_io(fd, bool(bm & 128), payload, len(data), bool(len(data) < length and len(data) % 64 == 0))
                emit(event='complete', seq=seq, setup=setup.hex(), result=r)
                if r >= 0 and configure:
                    configured = 1
                # Keep observing after transfer failures (e.g. a bus reset).
        finally:
            os.close(fd)
            emit(event='stop')

if __name__ == '__main__':
    main()

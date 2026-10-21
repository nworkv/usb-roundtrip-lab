#!/usr/bin/env python3
"""Compare EP0 IN submissions with USBPcap >=1.5 classic PCAP.
Convert PCAPNG with editcap -F pcap first. Only selected bus/device is read.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import struct


def packets(path):
    with open(path, 'rb') as f:
        head = f.read(24)
        endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
                  b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}.get(head[:4])
        if not endian or len(head) != 24:
            raise ValueError('Need classic PCAP: editcap -F pcap input.pcapng output.pcap')
        if struct.unpack(endian + 'I', head[20:24])[0] != 249:
            raise ValueError('Need LINKTYPE_USBPCAP (249)')
        while True:
            h = f.read(16)
            if not h:
                return
            if len(h) != 16:
                raise ValueError('Truncated PCAP record header')
            _, _, n, original = struct.unpack(endian + 'IIII', h)
            if n > 16 * 1024 * 1024:
                raise ValueError('Unreasonable packet size')
            data = f.read(n)
            if len(data) != n or n != original:
                raise ValueError('Truncated capture; use full snap length')
            yield data


def capture(path, bus, device):
    pending = {}
    rows = []
    for p in packets(path):
        if len(p) < 27:
            raise ValueError('Short USBPcap header')
        hlen, irp, status, function, info, b, d, ep, transfer, size = struct.unpack_from('<HQIHBHHBBI', p)
        if b != bus or d != device or transfer != 2 or ep & 15:
            continue
        if hlen < 28 or hlen > len(p) or hlen + size != len(p):
            raise ValueError('Invalid or truncated USBPcap control record')
        stage = p[27]
        data = p[hlen:]
        key = (b, d, irp)
        if stage == 0 and not info & 1:
            if len(data) < 8:
                raise ValueError('Missing SETUP bytes')
            if key in pending:
                raise ValueError('Reused IRP without completion; split capture into one run')
            row = dict(setup=data[:8].hex(), data=None, status=None)
            pending[key] = row
            if data[0] & 128:
                rows.append(row)
        elif stage == 3 and info & 1:
            row = pending.pop(key, None)
            if row is not None:
                row.update(data=data.hex(), status=status)
        elif stage in (1, 2):
            raise ValueError('USBPcap <1.5 is unsupported; update USBPcap')
    return rows


def compare(log, observed):
    submissions = []
    completed = {}
    for line in Path(log).read_text().splitlines():
        r = json.loads(line)
        if r['event'] == 'submit' and bytes.fromhex(r['setup'])[0] & 128:
            submissions.append(r)
        elif r['event'] == 'complete':
            completed[r['seq']] = r['result']
    expected = defaultdict(list)
    actual = defaultdict(list)
    for r in submissions:
        expected[r['setup']].append(r)
    for r in observed:
        actual[r['setup']].append(r)
    output = []
    for setup in sorted(expected.keys() | actual.keys()):
        left, right = expected[setup], actual[setup]
        # Do not shift-match repeated requests if capture/log omitted one.
        if len(left) != len(right):
            output.append(dict(setup=setup, verdict='AMBIGUOUS_COUNT',
                               linux_count=len(left), windows_count=len(right)))
            continue
        for a, b in zip(left, right):
            verdict = 'MATCH'
            n = completed.get(a['seq'])
            if n is None or n < 0:
                verdict = 'LINUX_INCOMPLETE_OR_ERROR'
            elif b['status'] is None:
                verdict = 'WINDOWS_COMPLETION_NOT_OBSERVED'
            elif b['status'] != 0:
                verdict = 'WINDOWS_TRANSFER_ERROR'
            elif n != len(bytes.fromhex(a['data'])):
                verdict = 'LINUX_SHORT_COMPLETION'
            elif a['data'] != b['data']:
                verdict = 'LENGTH_MISMATCH' if len(a['data']) != len(b['data']) else 'CONTENT_MISMATCH'
            row = dict(seq=a['seq'], setup=setup, verdict=verdict,
                       linux_hex=a['data'], windows_hex=b['data'],
                       linux_result=n, windows_status=b['status'])
            if b['data'] is not None:
                x, y = bytes.fromhex(a['data']), bytes.fromhex(b['data'])
                row['first_difference'] = next((i for i, (u, v) in enumerate(zip(x, y)) if u != v),
                                               min(len(x), len(y)) if len(x) != len(y) else None)
            output.append(row)
    if not output:
        output.append(dict(verdict='NO_COMPARABLE_TRANSFERS'))
    return output


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--log', required=True)
    ap.add_argument('--pcap', required=True)
    ap.add_argument('--bus', type=int, required=True)
    ap.add_argument('--device', type=int, required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    rows = compare(a.log, capture(a.pcap, a.bus, a.device))
    report = dict(summary=dict(Counter(r['verdict'] for r in rows)), transfers=rows)
    Path(a.out).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['summary']))
    raise SystemExit(0 if all(r['verdict'] == 'MATCH' for r in rows) else 2)

if __name__ == '__main__':
    main()

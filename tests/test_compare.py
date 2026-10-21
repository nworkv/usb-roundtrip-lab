import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
c = module('compare')
g = module('gadget')
SETUP = '8006000100001200'
DATA = '120100020000004034127856000100000001'

class Tests(unittest.TestCase):
    def test_response(self):
        _, d = g.load_case(ROOT / 'cases/vendor-ep0.json')
        self.assertEqual(g.response(bytes.fromhex(SETUP), d, 0).hex(), DATA)
        self.assertEqual(len(g.response(bytes.fromhex('8006000100000800'), d, 0)), 8)
        self.assertIsNone(g.response(bytes.fromhex('800600030904ff00'), d, 0))

    def fixture(self, directory, payload=DATA, status=0, complete=True):
        log = Path(directory) / 'sent.jsonl'
        log.write_text('\n'.join(json.dumps(r) for r in [
            dict(event='submit', seq=1, setup=SETUP, data=DATA),
            dict(event='complete', seq=1, result=18)]))
        def packet(stage, info, data):
            return struct.pack('<HQIHBHHBBIB', 28, 123, status, 8, info,
                               1, 2, 0x80, 2, len(data), stage) + data
        records = [packet(0, 0, bytes.fromhex(SETUP))]
        if complete:
            records.append(packet(3, 1, bytes.fromhex(payload)))
        pcap = Path(directory) / 'capture.pcap'
        raw = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 249)
        for p in records:
            raw += struct.pack('<IIII', 0, 0, len(p), len(p)) + p
        pcap.write_bytes(raw)
        return c.compare(log, c.capture(pcap, 1, 2))

    def test_match(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.fixture(d)[0]['verdict'], 'MATCH')

    def test_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            row = self.fixture(d, 'ff' + DATA[2:])[0]
            self.assertEqual(row['verdict'], 'CONTENT_MISMATCH')
            self.assertEqual(row['first_difference'], 0)

    def test_short(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.fixture(d, DATA[:8])[0]['verdict'], 'LENGTH_MISMATCH')

    def test_error(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.fixture(d, status=0xc0000001)[0]['verdict'], 'WINDOWS_TRANSFER_ERROR')

    def test_missing_completion(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.fixture(d, complete=False)[0]['verdict'], 'WINDOWS_COMPLETION_NOT_OBSERVED')

    def test_missing_record(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / 'log'
            log.write_text(json.dumps(dict(event='submit', seq=1, setup=SETUP, data=DATA)))
            self.assertEqual(c.compare(log, [])[0]['verdict'], 'AMBIGUOUS_COUNT')

    def test_empty(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / 'log'
            log.write_text('')
            self.assertEqual(c.compare(log, [])[0]['verdict'], 'NO_COMPARABLE_TRANSFERS')

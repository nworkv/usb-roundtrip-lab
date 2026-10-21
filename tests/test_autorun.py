import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import autorun

D=bytes.fromhex('120100020000004034127856000100000001')

def write_capture(path, devices):
    raw=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,262144,249)
    for dev in devices:
        p=struct.pack('<HQIHBHHBBIB',28,dev,0,8,1,1,dev,128,2,len(D),3)+D
        raw+=struct.pack('<IIII',0,0,len(p),len(p))+p
    path.write_bytes(raw)

class Tests(unittest.TestCase):
    def test_detect(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'cap'
            write_capture(p,[2])
            self.assertEqual(autorun.detect(p,D),(1,2))

    def test_ambiguous(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'cap'
            write_capture(p,[2,3])
            with self.assertRaises(RuntimeError):
                autorun.detect(p,D)

    def test_missing(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'cap'
            write_capture(p,[])
            with self.assertRaises(RuntimeError):
                autorun.detect(p,D)

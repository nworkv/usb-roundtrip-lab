#!/usr/bin/env python3
"""One-command EP0 experiment; Windows control through OpenSSH, no custom daemon."""
import argparse
import base64
from collections import Counter
import json
import os
from pathlib import Path
import queue
import struct
import subprocess as sp
import sys
import threading
import time
import uuid
import compare
import gadget

ROOT = Path(__file__).resolve().parent

REMOTE = r"""
$ErrorActionPreference='Stop'
$exe='C:\Program Files\Wireshark\dumpcap.exe'
if (!(Test-Path $exe)) { throw 'dumpcap.exe not found' }
$requested=__INTERFACE__
$listing=(& $exe -D 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw $listing }
$usb=@([regex]::Matches($listing,'(?m)^\d+\.\s+(\S*USBPcap\d+)') | ForEach-Object { $_.Groups[1].Value })
if ($requested -eq '') {
    if ($usb.Count -ne 1) { throw ('Choose interface in lab.json. Available: '+($usb -join ', ')) }
    $iface=$usb[0]
} else {
    if ($usb -notcontains $requested) { throw ('Interface not found: '+$requested+'; '+$listing) }
    $iface=$requested
}
$dir=Join-Path $env:TEMP ('usb-lab-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
$cap=Join-Path $dir 'capture.pcap'
$err=Join-Path $dir 'capture.err'
$out=Join-Path $dir 'capture.out'
$p=$null
try {
    $args=@('-i',$iface,'-P','-s','0','-q','-a','duration:__SECONDS__','-a','filesize:16384','-w',('"'+$cap+'"'))
    $p=Start-Process -FilePath $exe -ArgumentList $args -PassThru -NoNewWindow -RedirectStandardError $err -RedirectStandardOutput $out
    $deadline=[DateTime]::UtcNow.AddSeconds(15)
    while (!(Test-Path $cap) -or (Get-Item $cap).Length -lt 24) {
        if ($p.HasExited) { throw (Get-Content $err -Raw) }
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Capture start timeout' }
        Start-Sleep -Milliseconds 100
    }
    Start-Sleep -Milliseconds 500
    if ($p.HasExited) { throw (Get-Content $err -Raw) }
    [Console]::Out.WriteLine('READY')
    [Console]::Out.Flush()
    if (!$p.WaitForExit(__WAIT__)) { throw 'Capture completion timeout' }
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw (Get-Content $err -Raw) }
    $answer=@{pcap=[Convert]::ToBase64String([IO.File]::ReadAllBytes($cap)); log=(Get-Content $err -Raw); interface=$iface}
    [Console]::Out.WriteLine(($answer | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
} finally {
    if ($null -ne $p -and !$p.HasExited) { $p.Kill(); $p.WaitForExit() }
    Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
}
"""


def detect(pcap, descriptor):
    candidates=set()
    for p in compare.packets(pcap):
        if len(p) < 28:
            continue
        h, irp, status, fun, info, bus, dev, ep, kind, size = struct.unpack_from('<HQIHBHHBBI', p)
        if kind != 2 or ep & 15 or not info & 1 or p[27] != 3 or status or h > len(p):
            continue
        data=p[h:]
        if len(data) >= 8 and len(data) <= len(descriptor) and data == descriptor[:len(data)]:
            candidates.add((bus, dev))
    if len(candidates) != 1:
        raise RuntimeError('Cannot uniquely identify device; capture saved. Candidates: '+repr(candidates))
    return candidates.pop()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config', default='lab.json')
    ap.add_argument('--case', default='cases/vendor-ep0.json')
    a=ap.parse_args()
    cfg=json.loads(Path(a.config).read_text())
    host=cfg['ssh_host']
    if not host or host.startswith('-') or any(c.isspace() for c in host):
        raise ValueError('ssh_host must be a single SSH config alias or user@host')
    seconds=int(cfg.get('seconds', 15))
    if not 2 <= seconds <= 300:
        raise ValueError('seconds must be 2..300')
    _, descriptors=gadget.load_case(a.case)
    device=cfg.get('udc')
    if not device:
        names=list(Path('/sys/class/udc').iterdir())
        if len(names) != 1:
            raise RuntimeError('Select udc in lab.json')
        device=names[0].name
    driver=cfg.get('driver') or device
    if not Path('/dev/raw-gadget').exists():
        raise RuntimeError('Missing /dev/raw-gadget; load raw_gadget first')
    sp.run(['make','-C',str(ROOT)], check=True)
    if os.geteuid() != 0:
        sp.run(['sudo','-v'], check=True)
    run=ROOT/'runs'/(time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
    run.mkdir(parents=True)
    (run/'case.json').write_text(Path(a.case).read_text())
    interface=cfg.get('interface','')
    if any(c in interface for c in '\r\n\"'):
        raise ValueError('Invalid interface')
    literal="'"+interface.replace("'","''")+"'"
    remote=REMOTE.replace('__INTERFACE__',literal).replace('__SECONDS__',str(seconds+5)).replace('__WAIT__',str((seconds+25)*1000))
    encoded=base64.b64encode(remote.encode('utf-16le')).decode()
    ssh=['ssh','-T','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=3',host,
         'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand '+encoded]
    lines=queue.Queue()
    proc=None
    worker=None
    try:
        with open(run/'ssh.stderr','w') as err, open(run/'gadget.stderr','w') as ge:
            proc=sp.Popen(ssh, stdout=sp.PIPE, stderr=err, text=True, encoding='utf-8', errors='replace')
            def reader():
                for line in proc.stdout:
                    lines.put(line.rstrip('\r\n'))
                lines.put(None)
            threading.Thread(target=reader,daemon=True).start()
            first=lines.get(timeout=35)
            if first != 'READY':
                raise RuntimeError('Windows did not confirm capture; see ssh.stderr: '+repr(first))
            print('Capture ready; starting gadget', flush=True)
            command=[sys.executable,str(ROOT/'gadget.py'),str(run/'case.json'),
                     '--driver',driver,'--device',device,'--log',str(run/'sent.jsonl')]
            if os.geteuid() != 0:
                command=['sudo','-n']+command
            # GNU timeout bounds the gadget process even if autorun is interrupted.
            worker=sp.Popen(['timeout','--signal=INT','--kill-after=3s',str(seconds)+'s']+command,stderr=ge)
            worker.wait(timeout=seconds+10)
            answer=lines.get(timeout=40)
            if answer is None:
                raise RuntimeError('Remote capture failed; see ssh.stderr')
            result=json.loads(answer)
            raw=base64.b64decode(result.pop('pcap'),validate=True)
            pcap=run/'capture.pcap'
            pcap.write_bytes(raw)
            (run/'windows.json').write_text(json.dumps(result,indent=2))
            if proc.wait(timeout=10) != 0:
                raise RuntimeError('SSH failed after capture transfer')
            bus,dev=detect(pcap,descriptors[(1,0,0)])
            rows=compare.compare(run/'sent.jsonl',compare.capture(pcap,bus,dev))
            report=dict(bus=bus,device=dev,gadget_exit=worker.returncode,
                        summary=dict(Counter(r['verdict'] for r in rows)),transfers=rows)
            (run/'report.json').write_text(json.dumps(report,indent=2)+'\n')
            print(json.dumps(report['summary']))
            print('Artifacts:',run)
            return 0 if rows and all(r['verdict']=='MATCH' for r in rows) and worker.returncode in (0,124) else 2
    except (Exception, KeyboardInterrupt) as exc:
        (run/'error.txt').write_text(type(exc).__name__+': '+str(exc)+'\n')
        print('Run incomplete. Artifacts:',run,file=sys.stderr)
        return 3
    finally:
        # timeout controls privileged gadget children; wait rather than kill sudo alone.
        if worker is not None and worker.poll() is None:
            try:
                worker.wait(timeout=seconds+10)
            except sp.TimeoutExpired:
                print('Gadget may be stuck in kernel; disconnect test USB',file=sys.stderr)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except sp.TimeoutExpired:
                proc.kill()

if __name__ == '__main__':
    raise SystemExit(main())

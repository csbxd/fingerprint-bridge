#!/usr/bin/env python3
"""Independent loopback HTTPS integration lab. No public fingerprint service.

Requirements: openssl executable; pip install -r scripts/requirements-test.txt.
The lab origin is test infrastructure, not a change to production website A.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import traceback
import hpack

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

class SynCapture:
    """Linux optional capture; stores only initial loopback SYNs to the lab origin."""
    def __init__(self, interface, destination):
        self.destination=destination;self.packets={};self.stop=threading.Event()
        self.sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
        self.sock.bind((interface,0));self.sock.settimeout(.1)
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        while not self.stop.is_set():
            try: packet,address=self.sock.recvfrom(65536)
            except socket.timeout: continue
            if address[2]==4 or len(packet)<54 or packet[12:14]!=b'\x08\x00':continue
            ip=packet[14:];offset=(ip[0]&15)*4
            if ip[9]!=6 or ip[12:20]!=b'\x7f\x00\x00\x01'*2 or len(ip)<offset+20:continue
            tcp=ip[offset:];source,destination=struct.unpack('!HH',tcp[:4])
            if destination!=self.destination or tcp[13]&0x12!=2:continue
            self.packets.setdefault(source,packet)
    def pcap(self, source):
        packet=self.packets.get(source)
        if packet is None:raise AssertionError('initial SYN missing from capture')
        header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
        return header+struct.pack('<IIII',0,0,len(packet),len(packet))+packet
    def close(self):
        self.stop.set();self.thread.join(timeout=2);self.sock.close()

def exact(s, n):
    out = bytearray()
    while len(out) < n:
        b = s.recv(n-len(out))
        if not b:
            raise EOFError("truncated stream")
        out.extend(b)
    return bytes(out)

def head(s):
    out = bytearray()
    while not out.endswith(b"\r\n\r\n"):
        out.extend(exact(s, 1))
        if len(out) > 65536:
            raise ValueError("oversized head")
    return bytes(out)

def frame(kind, flags, stream, body):
    return len(body).to_bytes(3, "big") + bytes([kind, flags]) + struct.pack("!I", stream) + body

def read_frame(s):
    h = exact(s, 9)
    return h[3], h[4], int.from_bytes(h[5:9], "big"), exact(s, int.from_bytes(h[:3], "big"))

def hello_peek(s):
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        b = s.recv(256 * 1024, socket.MSG_PEEK)
        if not b:
            raise EOFError("no hello")
        offset = 0
        handshake = bytearray()
        while offset + 5 <= len(b):
            if b[offset] != 22:
                raise ValueError("expected TLS handshake record")
            size = int.from_bytes(b[offset+3:offset+5], "big")
            if size > 18432:
                raise ValueError("oversized TLS record")
            end = offset + 5 + size
            if end > len(b):
                break
            handshake.extend(b[offset+5:end])
            offset = end
            if len(handshake) >= 4:
                if handshake[0] != 1:
                    raise ValueError("expected ClientHello")
                needed = 4 + int.from_bytes(handshake[1:4], "big")
                if needed > 256 * 1024:
                    raise ValueError("oversized ClientHello")
                if len(handshake) >= needed:
                    return b[:offset]
        time.sleep(.001)
    raise TimeoutError("hello")

def certificates(path):
    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Fingerprint Bridge Lab CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
            "-keyout", str(path/"ca.key"), "-out", str(path/"ca.pem"))
    for name in ["a", "b"]:
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}.test", "-keyout", str(path/f"{name}.key"), "-out", str(path/f"{name}.csr"))
        (path/f"{name}.ext").write_text(f"subjectAltName=DNS:{name}.test\n"
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        openssl("x509", "-req", "-in", str(path/f"{name}.csr"), "-CA", str(path/"ca.pem"), "-CAkey", str(path/"ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(path/f"{name}.ext"), "-out", str(path/f"{name}.pem"))

class Origin:
    def __init__(self, path, protocol, connections=2):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0)); self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(path/"a.pem", path/"a.key")
        self.ctx.set_alpn_protocols([protocol])
        self.protocol = protocol
        self.connections=connections
        self.evidence = []; self.source_ports=[]; self.errors = []; self.done = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True); self.thread.start()

    def run(self):
        try:
            for _ in range(self.connections):
                raw, _ = self.listener.accept(); raw.settimeout(10)
                self.source_ports.append(raw.getpeername()[1])
                hello = hello_peek(raw)
                with self.ctx.wrap_socket(raw, server_side=True) as s:
                    if self.protocol == "h2":
                        http = self.h2(s)
                    else:
                        http = self.h1(s)
                    self.evidence.append((hello, http))
        except Exception:
            self.errors.append(traceback.format_exc())
        finally:
            self.listener.close(); self.done.set()

    def h1(self, s):
        requests = []
        for _ in range(2):
            h = head(s)
            body = exact(s, 7) if h.startswith(b"POST ") else b""
            requests.append({"head": h.decode("ascii"), "body_sha256": hashlib.sha256(body).hexdigest()})
            response = (f"HTTP/1.1 200 OK\r\nSet-Cookie: sid=from_A; Domain=a.test; Path=/; Secure; HttpOnly; SameSite=Lax\r\nSet-Cookie: hostonly=yes; Secure\r\nLocation: https://a.test:{self.port}/next%2Fpage?q=1\r\nContent-Length: 7\r\n\r\n".encode() + b"a\x00b\xffcde")
            s.sendall(response)
        return {"protocol":"HTTP/1.1", "requests":requests}

    def h2(self, s):
        assert exact(s, len(PREFACE)) == PREFACE
        s.sendall(frame(4, 0, 0, b""))
        decoder = hpack.Decoder(); encoder = hpack.Encoder()
        requests = []; controls = []; pending = {}; done = set()
        while len(done) < 2:
            kind, flags, stream, data = read_frame(s)
            if kind == 4:
                if flags == 0:
                    controls.append({"type":kind,"flags":flags,"stream":stream,"payload":data.hex()})
                    s.sendall(frame(4, 1, 0, b""))
            elif kind in (2, 8):
                controls.append({"type":kind,"flags":flags,"stream":stream,"payload":data.hex()})
            elif kind in (1, 9):
                if kind == 1:
                    pad = data[0] if flags & 8 else 0
                    start = (1 if flags & 8 else 0) + (5 if flags & 32 else 0)
                    priority = data[(1 if flags & 8 else 0):start].hex()
                    pending[stream] = [bytearray(data[start:len(data)-pad if pad else None]), flags & 1, priority]
                else:
                    pending[stream][0].extend(data)
                if flags & 4:
                    block, end, priority = pending.pop(stream)
                    headers = decoder.decode(bytes(block))
                    requests.append({"stream":stream,"headers":headers,"end_stream":end,"priority":priority})
                    done.add(stream)
                    out = encoder.encode([(':status','200'),('set-cookie','sid=from_A; Domain=a.test; Secure; HttpOnly'),('location',f'https://a.test:{self.port}/next'),('content-length','2')], huffman=True)
                    s.sendall(frame(1,4,stream,out)+frame(0,1,stream,b"OK"))
            else:
                raise AssertionError(f"unexpected request frame {kind}")
        # Drain late SETTINGS ACKs before close, otherwise an unread TCP receive
        # queue can reset the connection and discard the final response frames.
        try:
            while s.recv(65536):
                pass
        except (socket.timeout, ssl.SSLError):
            pass
        return {"protocol":"h2","controls":controls,"requests":requests}

def browser(path, protocol, host, port, authority):
    ctx = ssl.create_default_context(cafile=str(path/"ca.pem"))
    ctx.set_alpn_protocols([protocol]); ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("127.0.0.1",port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.settimeout(10)
            assert s.selected_alpn_protocol() == protocol
            if protocol == "http/1.1":
                for method in ["GET", "POST"]:
                    request = (f"{method} /test%2Fpath?q=1 HTTP/1.1\r\nhOsT:\t{authority} \r\nX-Order-Z: z\r\nCookie: sid=from_B; flag=yes\r\nReferer: https://{authority}/home\r\nX-Order-A: a\r\n" + ("Content-Length: 7\r\n" if method=="POST" else "") + "\r\n").encode()
                    s.sendall(request + (b"ab\x00c\xffde" if method=="POST" else b""))
                    h = head(s); assert exact(s,7)==b"a\x00b\xffcde"
                    assert f"Domain={host}".encode() in h
                    assert f"Location: https://{authority}/next%2Fpage?q=1".encode() in h
                    assert b"Set-Cookie: hostonly=yes; Secure" in h
            else:
                settings = b"".join(struct.pack("!HI",i,v) for i,v in [(1,65536),(2,0),(4,6291456),(6,262144)])
                s.sendall(PREFACE+frame(4,0,0,settings)+frame(8,0,0,struct.pack("!I",15663105))+frame(2,0,3,bytes([0,0,0,0,200])))
                encoder=hpack.Encoder()
                for stream in [1,3]:
                    headers=[(':method','GET'),(':authority',authority),(':scheme','https'),(':path',f'/stream/{stream}'),('x-z','z'),('cookie','sid=from_B; flag=yes'),('x-a','a'),('x-a','second')]
                    block=encoder.encode(headers,huffman=True)
                    # Padding and priority precede a fragmented HPACK block.
                    s.sendall(frame(1,0x29,stream,bytes([2,0,0,0,0,255])+block[:5]+b'\x00\x00')+frame(9,4,stream,block[5:]))
                decoder=hpack.Decoder(); finished=set(); blocks={}
                while len(finished)<2:
                    kind,flags,stream,data=read_frame(s)
                    if kind==4 and not flags&1:s.sendall(frame(4,1,0,b""))
                    elif kind in (1,9):
                        blocks.setdefault(stream,bytearray()).extend(data)
                        if flags&4:
                            headers=decoder.decode(bytes(blocks.pop(stream)))
                            assert ('set-cookie',f'sid=from_A; Domain={host}; Secure; HttpOnly') in headers
                            assert ('location',f'https://{authority}/next') in headers
                    elif kind==0:
                        assert data==b'OK'
                        if flags&1:finished.add(stream)

def start_bridge(binary, path, origin, reports, extra=None):
    with socket.socket() as free:
        free.bind(("127.0.0.1",0)); port=free.getsockname()[1]
    log=open(path/f'bridge-{port}.log','w+')
    command=[str(binary),'serve','--listen',f'127.0.0.1:{port}','--public',f'b.test:{port}','--upstream',f'a.test:{origin.port}','--connect',f'127.0.0.1:{origin.port}','--cert',str(path/'b.pem'),'--key',str(path/'b.key'),'--ca',str(path/'ca.pem'),'--reports',str(reports),'--handshake-timeout','10']
    extra=list(extra or [])
    while extra:
        flag=extra.pop(0)
        if extra and not extra[0].startswith('--'):
            value=extra.pop(0)
            if flag in command:command[command.index(flag)+1]=value
            else:command.extend([flag,value])
        else:command.append(flag)
    proc=subprocess.Popen(command,stdout=log,stderr=log)
    for _ in range(100):
        log.seek(0)
        if 'bridge ready' in log.read():return proc,port,log
        if proc.poll() is not None:
            log.seek(0);raise RuntimeError('bridge failed to start: '+log.read())
        time.sleep(.05)
    proc.terminate();raise TimeoutError('bridge startup')

def run(binary, output, capture_interface=None):
    output.mkdir(parents=True,exist_ok=True)
    results=[]
    with tempfile.TemporaryDirectory(prefix='fingerprint-bridge-lab-') as temp:
        path=Path(temp);certificates(path)
        for protocol in ['http/1.1','h2']:
            origin=Origin(path,protocol)
            capture=SynCapture(capture_interface,origin.port) if capture_interface else None
            reports=path/('runtime-'+protocol.replace('/','-'))
            proc,port,log=start_bridge(binary,path,origin,reports)
            try:
                browser(path,protocol,'a.test',origin.port,f'a.test:{origin.port}')
                browser(path,protocol,'b.test',port,f'b.test:{port}')
                assert origin.done.wait(10), 'origin did not finish'
                assert not origin.errors, origin.errors
                assert len(origin.evidence)==2
                docs=[]
                for index,(side,(wire,http)) in enumerate(zip(['direct','bridged'],origin.evidence)):
                    tls_file=path/f'{side}.tls';tls_file.write_bytes(wire)
                    doc=json.loads(subprocess.check_output([str(binary),'inspect-hello',str(tls_file)]))
                    doc['http']=http;doc['tcp']=None
                    if capture:
                        packet_file=path/f'{side}.pcap';packet_file.write_bytes(capture.pcap(origin.source_ports[index]))
                        doc.update(json.loads(subprocess.check_output([str(binary),'inspect-pcap',str(packet_file)])))
                    name=protocol.replace('/','-')+'.'+side+'.json'
                    (output/name).write_text(json.dumps(doc,indent=2)+'\n');docs.append(output/name)
                compared=subprocess.run([str(binary),'compare',*map(str,docs),'--layers','http'],capture_output=True,text=True)
                assert compared.returncode==0,compared.stdout+compared.stderr
                tls_diff=subprocess.run([str(binary),'compare',*map(str,docs),'--layers','tls'],capture_output=True,text=True)
                assert tls_diff.returncode in (0,1),tls_diff.stderr
                full=subprocess.run([str(binary),'compare',*map(str,docs)],capture_output=True,text=True)
                assert full.returncode in (0,1),full.stderr
                if not capture:assert full.returncode==1 and 'tcp' in json.loads(full.stdout)['missing_layers']
                # An intentional TCP mismatch is a failure, independent of TLS tests.
                negative=path/'negative.json';negative.write_text(json.dumps({'tcp':{'window':123}}))
                baseline=path/'baseline.json';baseline.write_text(json.dumps({'tcp':{'window':456}}))
                assert subprocess.run([str(binary),'compare',str(baseline),str(negative),'--layers','tcp'],stdout=subprocess.DEVNULL).returncode==1
                tcp_result='not captured: raw-socket privileges required'
                if capture:
                    tcp_compare=subprocess.run([str(binary),'compare',*map(str,docs),'--layers','tcp'],capture_output=True,text=True)
                    assert tcp_compare.returncode in (0,1),tcp_compare.stderr
                    tcp_result=json.loads(tcp_compare.stdout)
                results.append({'protocol':protocol,'http_match':True,'tls':json.loads(tls_diff.stdout),'tcp':tcp_result,'independent_origin_capture':True})
            except Exception:
                time.sleep(.1)
                log.flush();log.seek(0)
                print('bridge exit:',proc.poll(),log.read(),'origin errors:',origin.errors,flush=True)
                raise
            finally:
                proc.terminate();proc.wait(timeout=10);log.close()
                if capture:capture.close()
        # Verify the CLI rejects absent evidence instead of producing a false pass.
        (path/'empty.json').write_text('{}')
        assert subprocess.run([str(binary),'compare',str(path/'empty.json'),str(path/'empty.json')],stdout=subprocess.DEVNULL).returncode==1
        security=[]
        for mode in ['wrong_hostname','untrusted_ca','strict_tls']:
            origin=Origin(path,'http/1.1',connections=1)
            extra={'wrong_hostname':['--upstream',f'wrong.test:{origin.port}'],'untrusted_ca':['--ca',str(path/'b.pem')],'strict_tls':['--strict-tls']}[mode]
            reports=path/mode
            proc,port,log=start_bridge(binary,path,origin,reports,extra)
            try:
                try: browser(path,'http/1.1','b.test',port,f'b.test:{port}')
                except (ssl.SSLError,EOFError,ConnectionResetError):pass
                else:raise AssertionError(f'{mode} unexpectedly accepted a request')
                assert origin.done.wait(10)
                assert not origin.evidence, 'HTTP reached origin despite rejection'
                if mode=='strict_tls':
                    report_files=list(reports.glob('*.report.json'))
                    assert report_files and json.loads(report_files[0].read_text())['comparison']['pass'] is False
                security.append({'case':mode,'rejected_before_http':True})
            finally:
                proc.terminate();proc.wait(timeout=10);log.close()
    summary={'lab_pass':True,'scope':'loopback Python/OpenSSL client, HTTP/1.1 and HTTP/2; no Chrome/Firefox/Safari certification','results':results,'security_checks':security}
    (output/'lab-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,default=Path('target/debug/fingerprint-bridge'));parser.add_argument('--output',type=Path,default=Path('test-results/lab'));parser.add_argument('--capture-interface',help='Linux interface, normally lo; requires CAP_NET_RAW/root; capture failure is fatal')
    args=parser.parse_args();run(args.binary.resolve(),args.output.resolve(),args.capture_interface)

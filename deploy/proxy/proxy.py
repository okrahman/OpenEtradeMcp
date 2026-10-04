"""Bounded HTTPS CONNECT proxy. It does not terminate upstream TLS.
Exact hostname + port + public pinned IPv4 + matching ClientHello SNI are required.
No request headers, credentials, destinations, or payloads are written to logs.
"""
import asyncio
import ipaddress
import os
import socket
import struct
import json
import ssl
import urllib.parse


def destination(authority, allowed):
    if authority.count(':') != 1:
        raise ValueError('denied')
    host, port = authority.split(':')
    if host not in allowed or port != '443' or host.lower() != host:
        raise ValueError('denied')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError('denied')


def public(ip):
    value = ipaddress.ip_address(ip)
    return value.version == 4 and value.is_global


def sni(hello):
    if len(hello) < 4 or hello[0] != 1 or int.from_bytes(hello[1:4], 'big') != len(hello) - 4:
        raise ValueError('invalid TLS hello')
    body = memoryview(hello)[4:]
    offset = 34
    def take(length):
        nonlocal offset
        if offset + length > len(body):
            raise ValueError('truncated hello')
        result = body[offset:offset + length]
        offset += length
        return result
    def number(length):
        return int.from_bytes(take(length), 'big')
    take(number(1))
    take(number(2))
    take(number(1))
    length = number(2)
    end = offset + length
    if end != len(body):
        raise ValueError('invalid extensions')
    names = []
    seen = set()
    while offset < end:
        kind, size = number(2), number(2)
        if kind in seen or kind == 0xfe0d:
            raise ValueError('duplicate or encrypted extension')
        seen.add(kind)
        extension = take(size)
        if kind == 0:
            if len(extension) < 5 or int.from_bytes(extension[:2], 'big') != len(extension) - 2:
                raise ValueError('invalid SNI')
            pos = 2
            while pos < len(extension):
                if pos + 3 > len(extension):
                    raise ValueError('invalid SNI')
                typ = extension[pos]
                n = int.from_bytes(extension[pos+1:pos+3], 'big')
                pos += 3
                if typ != 0 or pos + n > len(extension):
                    raise ValueError('invalid SNI')
                names.append(bytes(extension[pos:pos+n]).decode('ascii'))
                pos += n
    if len(names) != 1:
        raise ValueError('one SNI required')
    return names[0]


async def client_hello(reader):
    records = bytearray()
    handshake = bytearray()
    expected = None
    while expected is None or len(handshake) < expected:
        header = await reader.readexactly(5)
        size = int.from_bytes(header[3:5], 'big')
        if header[0] != 22 or header[1] != 3 or size > 16384 or len(records) + size > 32768:
            raise ValueError('invalid TLS record')
        payload = await reader.readexactly(size)
        records.extend(header + payload)
        handshake.extend(payload)
        if len(handshake) >= 4:
            expected = 4 + int.from_bytes(handshake[1:4], 'big')
            if expected > 32768:
                raise ValueError('large handshake')
    if len(handshake) != expected:
        raise ValueError('unexpected handshake data')
    return bytes(records), sni(handshake)


async def handle(reader, writer, allowed):
    upstream = None
    try:
        raw = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
        if len(raw) > 4096:
            raise ValueError('large CONNECT')
        lines = raw.decode('ascii').split('\r\n')
        method, authority, protocol = lines[0].split(' ')
        if method != 'CONNECT' or protocol != 'HTTP/1.1':
            raise ValueError('CONNECT only')
        host = destination(authority, allowed)
        addresses = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM), 5)
        if not addresses or any(not public(a[4][0]) for a in addresses):
            raise ValueError('nonpublic address')
        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        await writer.drain()
        hello, server_name = await asyncio.wait_for(client_hello(reader), 5)
        if server_name != host:
            raise ValueError('SNI mismatch')
        # Connect to the checked address, with no second DNS resolution (rebinding protection).
        remote, upstream = await asyncio.wait_for(asyncio.open_connection(addresses[0][4][0], 443, family=socket.AF_INET), 5)
        upstream.write(hello)
        await upstream.drain()
        async def copy(src, dst):
            while data := await src.read(16384):
                dst.write(data)
                await dst.drain()
        tasks = [asyncio.create_task(copy(reader, upstream)), asyncio.create_task(copy(remote, writer))]
        try:
            await asyncio.wait(tasks, timeout=60, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    except (ValueError, OSError, UnicodeError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        pass
    finally:
        if upstream:
            upstream.close()
        writer.close()
        await writer.wait_closed()


GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO = 'https://www.googleapis.com/oauth2/v3/userinfo'


def fetch_policy(request, approved):
    if set(request) != {'url', 'method', 'bearer', 'form'}:
        raise ValueError('typed fetch required')
    url, method, bearer, form = (request[k] for k in ('url','method','bearer','form'))
    if not isinstance(url,str) or not isinstance(method,str) or len(url)>2048 or any(ord(c)<33 or ord(c)>126 for c in url):
        raise ValueError('invalid endpoint')
    if url == GOOGLE_TOKEN and method == 'POST' and bearer is None and isinstance(form,str):
        fields = urllib.parse.parse_qs(form, strict_parsing=True)
        if not fields or any(len(v) != 1 for v in fields.values()) or set(fields) - {'client_id','client_secret','code','grant_type','redirect_uri','code_verifier'}:
            raise ValueError('invalid Google token request')
        if fields.get('grant_type') != ['authorization_code']:
            raise ValueError('authorization-code flow required')
    elif url == GOOGLE_USERINFO and method == 'GET' and form is None and isinstance(bearer,str) and len(bearer) <= 8192:
        if not bearer or any(ord(c) < 33 or ord(c) > 126 for c in bearer):
            raise ValueError('invalid bearer')
    elif url in approved and method == 'GET' and bearer is None and form is None:
        pass
    else:
        raise ValueError('unapproved endpoint')
    uri = urllib.parse.urlsplit(url)
    if uri.scheme != 'https' or uri.port not in (None,443) or uri.username or uri.password or uri.fragment:
        raise ValueError('HTTPS endpoint required')
    return uri


async def identity_fetch(reader, writer, approved):
    upstream = None
    try:
        raw = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),5)
        if len(raw)>4096: raise ValueError('large request')
        lines=raw.decode('ascii').split('\r\n')
        if lines[0]!='POST /fetch HTTP/1.1': raise ValueError('typed fetch only')
        headers={}
        for line in lines[1:]:
            if not line: continue
            name,value=line.split(':',1);name=name.lower()
            if name in headers: raise ValueError('duplicate header')
            headers[name]=value.strip()
        if 'transfer-encoding' in headers: raise ValueError('chunked requests denied')
        size=int(headers.get('content-length','0'))
        if size<=0 or size>32768: raise ValueError('bounded request required')
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError('duplicate JSON')
                result[key]=value
            return result
        request=json.loads(await asyncio.wait_for(reader.readexactly(size),5),object_pairs_hook=unique)
        uri=fetch_policy(request,approved)
        addresses=await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(uri.hostname,443,family=socket.AF_INET,type=socket.SOCK_STREAM),5)
        if not addresses or any(not public(a[4][0]) for a in addresses):raise ValueError('nonpublic endpoint')
        tls=ssl.create_default_context()
        remote,upstream=await asyncio.wait_for(asyncio.open_connection(addresses[0][4][0],443,ssl=tls,server_hostname=uri.hostname),5)
        target=uri.path or '/'
        if uri.query:target+='?'+uri.query
        payload=request['form'].encode('utf-8') if request['form'] is not None else b''
        lines=[request['method']+' '+target+' HTTP/1.1','Host: '+uri.hostname,'Connection: close','Accept: application/json']
        if request['bearer'] is not None:lines.append('Authorization: Bearer '+request['bearer'])
        if payload:lines.extend(['Content-Type: application/x-www-form-urlencoded','Content-Length: '+str(len(payload))])
        upstream.write(('\r\n'.join(lines)+'\r\n\r\n').encode('ascii')+payload);await upstream.drain()
        head=await asyncio.wait_for(remote.readuntil(b'\r\n\r\n'),5)
        if len(head)>8192:raise ValueError('large response headers')
        parts=head.decode('ascii').split('\r\n');status=int(parts[0].split(' ')[1]);response_headers={}
        for line in parts[1:]:
            if line:
                name,value=line.split(':',1);response_headers[name.lower()]=value.strip()
        # Redirects and compression are rejected. Read at most 32KiB within the total request deadline.
        if 300<=status<400 or response_headers.get('content-encoding') not in (None,'identity'):raise ValueError('redirect/compression denied')
        body=bytearray()
        if response_headers.get('transfer-encoding')=='chunked':
            while True:
                line=await remote.readuntil(b'\r\n')
                if len(line)>32:raise ValueError('large chunk header')
                chunk=int(line.strip(),16)
                if chunk==0:break
                if chunk<0 or len(body)+chunk>32768:raise ValueError('large response')
                body.extend(await remote.readexactly(chunk))
                if await remote.readexactly(2)!=b'\r\n':raise ValueError('invalid chunk')
        elif 'content-length' in response_headers:
            length=int(response_headers['content-length'])
            if length<0 or length>32768:raise ValueError('large response')
            body.extend(await remote.readexactly(length))
        else:
            while chunk:=await remote.read(4096):
                if len(body)+len(chunk)>32768:raise ValueError('large response')
                body.extend(chunk)
        encoded=json.dumps({'status':status,'body':body.decode('utf-8')}).encode()
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(encoded)).encode()+b'\r\n\r\n'+encoded);await writer.drain()
    finally:
        if upstream:upstream.close()
        writer.close();await writer.wait_closed()


async def main():
    mode=os.environ.get('MODE','brokerage')
    allowed=frozenset(os.environ.get('ALLOWED_HOSTS','api.etrade.com').split(','))
    approved=frozenset(json.load(open('/app/approved-urls.json'))) if mode=='identity' else frozenset()
    tls=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,cafile='/run/secrets/ca.crt')
    tls.load_cert_chain('/run/secrets/service.crt','/run/secrets/service.key')
    tls.verify_mode=ssl.CERT_REQUIRED
    tls.minimum_version=ssl.TLSVersion.TLSv1_2
    expected='authorization' if mode=='identity' else 'gateway'
    slots=asyncio.Semaphore(16)
    async def accept(reader,writer):
        certificate=writer.get_extra_info('peercert') or {}
        names=[value for kind,value in certificate.get('subjectAltName',()) if kind=='DNS']
        if names != [expected] or slots.locked():
            writer.close();return
        async with slots:
            try:
                if mode=='identity':await asyncio.wait_for(identity_fetch(reader,writer,approved),10)
                else:await handle(reader,writer,allowed)
            except (ValueError,OSError,UnicodeError,asyncio.TimeoutError,asyncio.IncompleteReadError,asyncio.LimitOverrunError):
                writer.close()
    server=await asyncio.start_server(accept,'0.0.0.0',3128,limit=8192,ssl=tls,ssl_handshake_timeout=5)
    async with server:await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())

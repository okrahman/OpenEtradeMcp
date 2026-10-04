import asyncio
import importlib.util
import pathlib
import struct
import unittest
from unittest.mock import AsyncMock, patch
spec = importlib.util.spec_from_file_location('proxy', pathlib.Path(__file__).parents[1] / 'deploy/proxy/proxy.py')
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


def hello(host, extra=b''):
    encoded = host.encode()
    name = b'\x00' + struct.pack('!H', len(encoded)) + encoded
    extension = struct.pack('!HHH', 0, len(name)+2, len(name)) + name + extra
    body = b'\x03\x03' + bytes(32) + b'\x00' + b'\x00\x02\x13\x01' + b'\x01\x00' + struct.pack('!H',len(extension)) + extension
    return b'\x01' + len(body).to_bytes(3,'big') + body


class ProxyTests(unittest.TestCase):
    def test_exact_production_authority(self):
        self.assertEqual(proxy.destination('api.etrade.com:443', {'api.etrade.com'}), 'api.etrade.com')
        for value in ('apisb.etrade.com:443', 'api.etrade.com.evil:443', 'api.etrade.com:80', 'API.ETRADE.COM:443', '127.0.0.1:443', '[::1]:443', '169.254.169.254:443', 'api.etrade.com.:443'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                proxy.destination(value, {'api.etrade.com'})
    def test_private_and_ipv6_addresses(self):
        for ip in ('127.0.0.1','169.254.169.254','10.0.0.1','100.64.0.1','192.168.0.1','172.16.0.1','::1','2001:4860:4860::8888','::ffff:8.8.8.8','198.18.0.1'):
            self.assertFalse(proxy.public(ip),ip)
        self.assertTrue(proxy.public('8.8.8.8'))
    def test_exact_sni(self):
        self.assertEqual(proxy.sni(hello('api.etrade.com')), 'api.etrade.com')
        self.assertNotEqual(proxy.sni(hello('evil.test')), 'api.etrade.com')
    def test_duplicate_sni_and_encrypted_clienthello_denied(self):
        for extension in (b'\x00\x00\x00\x00', b'\xfe\x0d\x00\x00'):
            with self.assertRaises(ValueError):proxy.sni(hello('api.etrade.com',extension))
    def test_truncated_hello_denied(self):
        for offset in (1,4,20,35,40):
            with self.assertRaises(ValueError):proxy.sni(hello('api.etrade.com')[:offset])


class AsyncProxyTests(unittest.IsolatedAsyncioTestCase):
    async def test_fragmented_hello(self):
        message = hello('api.etrade.com')
        reader = asyncio.StreamReader()
        for chunk in (message[:3],message[3:20],message[20:]):
            reader.feed_data(b'\x16\x03\x03'+len(chunk).to_bytes(2,'big')+chunk)
        reader.feed_eof()
        raw,name=await proxy.client_hello(reader)
        self.assertEqual(name,'api.etrade.com')
        self.assertLess(len(raw),32768)
    async def test_no_tls_or_oversized_tls_denied(self):
        for record in (b'\x17\x03\x03\x00\x01x', b'\x16\x03\x03\xff\xff'):
            reader=asyncio.StreamReader();reader.feed_data(record);reader.feed_eof()
            with self.assertRaises(ValueError):await proxy.client_hello(reader)
    async def test_dns_rebinding_private_result_never_connects(self):
        reader=asyncio.StreamReader();reader.feed_data(b'CONNECT api.etrade.com:443 HTTP/1.1\r\nHost: api.etrade.com:443\r\n\r\n');reader.feed_eof()
        class Writer:
            closed=False
            def write(self,data):raise AssertionError('must not accept CONNECT')
            async def drain(self):pass
            def close(self):self.closed=True
            async def wait_closed(self):pass
        writer=Writer();loop=asyncio.get_running_loop()
        with patch.object(loop,'getaddrinfo',AsyncMock(return_value=[(2,1,6,'',('169.254.169.254',443))])),patch.object(asyncio,'open_connection',AsyncMock()) as connect:
            await proxy.handle(reader,writer,{'api.etrade.com'})
            connect.assert_not_called()
        self.assertTrue(writer.closed)

class IdentityFetchPolicyTests(unittest.TestCase):
    def test_exact_url_and_method(self):
        proxy.fetch_policy({'url':proxy.GOOGLE_USERINFO,'method':'GET','bearer':'fixture-token','form':None},set())
        proxy.fetch_policy({'url':'https://client.example/metadata.json','method':'GET','bearer':None,'form':None},{'https://client.example/metadata.json'})
        for request in (
            {'url':'https://www.googleapis.com/arbitrary','method':'GET','bearer':'fixture','form':None},
            {'url':'https://client.example/other.json','method':'GET','bearer':None,'form':None},
            {'url':'https://client.example/metadata.json','method':'GET','bearer':'leak','form':None},
            {'url':proxy.GOOGLE_TOKEN,'method':'POST','bearer':None,'form':'grant_type=client_credentials'},
            {'url':proxy.GOOGLE_USERINFO,'method':'GET','bearer':'x\r\nInjected:true','form':None}):
            with self.assertRaises(ValueError):proxy.fetch_policy(request,{'https://client.example/metadata.json'})
    def test_google_token_fields_are_bounded_to_auth_code(self):
        proxy.fetch_policy({'url':proxy.GOOGLE_TOKEN,'method':'POST','bearer':None,'form':'grant_type=authorization_code&code=fixture&client_id=fixture'},set())
        with self.assertRaises(ValueError):proxy.fetch_policy({'url':proxy.GOOGLE_TOKEN,'method':'POST','bearer':None,'form':'grant_type=authorization_code&url=evil'},set())

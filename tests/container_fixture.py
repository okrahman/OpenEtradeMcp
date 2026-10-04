#!/usr/bin/env python3
"""Local nonfinancial container/TLS smoke checks. No brokerage credentials or sandbox access.
Leaves a named stopped fixture stack for the privileged network acceptance step.
"""
import json
import os
import pathlib
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
root = pathlib.Path(__file__).resolve().parents[1]
state = pathlib.Path(tempfile.mkdtemp(prefix='etrade-container-'))
os.chmod(state, 0o711)
pins = json.load(open(root/'deploy/base-images.json'))

def run(*args, **kwargs):
    return subprocess.run(args, check=True, cwd=root, **kwargs)

def openssl(*args):
    run('openssl', *args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

secrets = state/'secrets'
secrets.mkdir()
ca = state/'ca'
ca.mkdir()
openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(ca/'key'),'-out',str(ca/'cert'),'-days','2','-subj','/CN=fixture-internal-ca','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
for name in ('ingress','mcp','authorization','gateway','brokerage-proxy','identity-proxy'):
    path=secrets/name
    path.mkdir(mode=0o700)
    openssl('req','-newkey','rsa:2048','-nodes','-keyout',str(path/'service.key'),'-out',str(path/'request'),'-subj','/CN='+name)
    (path/'extensions').write_text('subjectAltName=DNS:'+name+'\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\n')
    openssl('x509','-req','-in',str(path/'request'),'-CA',str(ca/'cert'),'-CAkey',str(ca/'key'),'-CAcreateserial','-out',str(path/'service.crt'),'-days','2','-extfile',str(path/'extensions'))
    openssl('pkcs12','-export','-inkey',str(path/'service.key'),'-in',str(path/'service.crt'),'-out',str(path/'service.pfx'),'-passout','pass:')
    (path/'ca.crt').write_bytes((ca/'cert').read_bytes())
    for file in path.iterdir():os.chmod(file,0o600)
# Distinct token keys; fixture bootstrap output is captured and discarded.
for name in ('token-signing','token-encryption'):
    path=secrets/'authorization'
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(state/(name+'.key')),'-out',str(state/(name+'.crt')),'-days','2','-subj','/CN='+name)
    openssl('pkcs12','-export','-inkey',str(state/(name+'.key')),'-in',str(state/(name+'.crt')),'-out',str(path/(name+'.pfx')),'-passout','pass:')
openssl('genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(secrets/'authorization/assertion-private.pem'))
openssl('pkey','-in',str(secrets/'authorization/assertion-private.pem'),'-pubout','-out',str(secrets/'gateway/assertion-public.pem'))
(secrets/'authorization/google-client-secret').write_text('nonfinancial-fixture')
fixture=secrets/'gateway-fixture'
fixture.mkdir(mode=0o700)
for name in ('service.pfx','ca.crt','assertion-public.pem'):(fixture/name).write_bytes((secrets/'gateway'/name).read_bytes())
# Public leaf is signed by fixture CA and trusted only by this script.
p=secrets/'ingress'
openssl('req','-newkey','rsa:2048','-nodes','-keyout',str(p/'public.key'),'-out',str(state/'public.request'),'-subj','/CN=localhost')
(state/'public.extensions').write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
openssl('x509','-req','-in',str(state/'public.request'),'-CA',str(ca/'cert'),'-CAkey',str(ca/'key'),'-CAcreateserial','-out',str(p/'public.crt'),'-days','2','-extfile',str(state/'public.extensions'))
(p/'ingress.pfx.pem').write_bytes((p/'service.crt').read_bytes());(p/'ingress.key').write_bytes((p/'service.key').read_bytes())
for directory in secrets.iterdir():
    for file in directory.iterdir():os.chmod(file,0o600)
for name in ('authorization','gateway'):(state/name).mkdir(mode=0o700)
env=state/'fixture.env'
env.write_text('\n'.join(['DOMAIN=localhost','OWNER_SUBJECT=fixture-owner','GOOGLE_CLIENT_ID=fixture-client',
    'SECRETS_ROOT='+str(secrets),'STATE_ROOT='+str(state),
    'INGRESS_IMAGE='+pins['nginx'],'MCP_IMAGE=etrade-local-mcp','AUTHORIZATION_IMAGE=etrade-local-authorization','GATEWAY_IMAGE=etrade-local-gateway',
    'BROKERAGE_PROXY_IMAGE=etrade-local-proxy','IDENTITY_PROXY_IMAGE=etrade-local-proxy'])+'\n')
# Materialize an isolated local configuration and replace the port list entirely.
base=['docker','compose','--env-file',str(env),'-f',str(root/'deploy/compose.yaml'),'-f',str(root/'deploy/compose.fixtures.yaml')]
materialized=json.loads(subprocess.check_output(base+['config','--format','json'],cwd=root))
for service in materialized['services'].values():
    service['user']=str(os.getuid())+':'+str(os.getgid())
    for volume in service.get('volumes',[]):
        if volume.get('type')=='bind':volume.setdefault('bind',{})['selinux']='Z'
    service['tmpfs']=['/tmp:rw,noexec,nosuid,size=64m,uid='+str(os.getuid())+',gid='+str(os.getgid())]
materialized['services']['ingress']['ports']=[{'target':8443,'published':'18443','host_ip':'127.0.0.1','protocol':'tcp'}]
materialized['services']['authorization']['environment'].update(Issuer='https://localhost',Resource='https://localhost/mcp')
materialized['services']['mcp']['environment']['PublicOrigin']='https://localhost'
override=state/'fixture.json';override.write_text(json.dumps(materialized))
compose=['docker','compose','-f',str(override)]
(root/'tests/.fixture-command.json').write_text(json.dumps(compose))
try:
    run(*compose,'config','--quiet')
    run(*compose,'run','--rm','--no-deps','authorization','--provision-owner',stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    (state/'authorization/owner-bootstrap.txt').unlink()
    run(*compose,'up','-d')
    context=ssl.create_default_context(cafile=str(ca/'cert'))
    for attempt in range(40):
        try:
            with urllib.request.urlopen('https://localhost:18443/.well-known/oauth-protected-resource',context=context,timeout=2) as response:
                assert json.load(response)['resource']=='https://localhost/mcp'
            break
        except (urllib.error.URLError,TimeoutError) as error:last_error=error;time.sleep(1)
    else:raise AssertionError('fixture HTTPS startup failed: '+str(last_error))
    for path,expected in (('/mcp',401),('/internal/consume',404),('/admin/status',404)):
        try:urllib.request.urlopen('https://localhost:18443'+path,context=context,timeout=3)
        except urllib.error.HTTPError as error:assert error.code==expected,(path,error.code)
        else:raise AssertionError('unexpected public route access: '+path)
    # Independent mTLS proxy roles and exact-destination denials, with zero provider connections.
    import socket
    def proxy_denies(service,peer,payload):
        network_ip='172.30.16.3' if service=='identity-proxy' else '172.30.15.3'
        tls=ssl.create_default_context(cafile=str(ca/'cert'))
        tls.load_cert_chain(str(secrets/peer/'service.crt'),str(secrets/peer/'service.key'))
        with socket.create_connection((network_ip,3128),timeout=3) as socket_raw:
            with tls.wrap_socket(socket_raw,server_hostname=service) as socket_tls:
                socket_tls.sendall(payload)
                try:reply=socket_tls.recv(8192)
                except (ssl.SSLError,ConnectionResetError):reply=b''
                assert reply==b'',(service,peer)
    content=json.dumps({'url':'https://www.googleapis.com/arbitrary','method':'GET','bearer':None,'form':None}).encode()
    fetch=b'POST /fetch HTTP/1.1\r\nHost: identity-proxy\r\nContent-Length: '+str(len(content)).encode()+b'\r\n\r\n'+content
    proxy_denies('identity-proxy','authorization',fetch)
    proxy_denies('identity-proxy','mcp',fetch)
    proxy_denies('brokerage-proxy','gateway',b'CONNECT apisb.etrade.com:443 HTTP/1.1\r\nHost: apisb.etrade.com:443\r\n\r\n')
    proxy_denies('brokerage-proxy','mcp',b'CONNECT apisb.etrade.com:443 HTTP/1.1\r\n\r\n')
    ids=subprocess.check_output(compose+['ps','-q'],cwd=root,text=True).split()
    for identity in ids:
        info=json.loads(subprocess.check_output(['docker','inspect',identity]))[0]
        assert info['HostConfig']['ReadonlyRootfs']
        assert info['Config']['User'] not in ('0','0:0','root','')
        assert info['HostConfig']['CapDrop']==['ALL']
        assert not info['HostConfig']['Privileged']
        assert info['HostConfig']['NetworkMode']!='host'
        assert all(m['Destination']!='/var/run/docker.sock' for m in info['Mounts'])
        assert all(not m['Destination'].startswith('/run/secrets') or not m['RW'] for m in info['Mounts'])
        if info['Name'].endswith('gateway-1'):
            assert next(m['Source'] for m in info['Mounts'] if m['Destination']=='/run/secrets')==str(fixture)
            assert set(f.name for f in fixture.iterdir())=={'service.pfx','ca.crt','assertion-public.pem'}
    print('PASS: fixture HTTPS metadata, authenticated MCP boundary, hidden internal APIs, non-root/read-only containers, credential-free fixture gateway, mTLS proxy role and exact-destination denials')
finally:
    run(*compose,'stop',stdout=subprocess.DEVNULL)

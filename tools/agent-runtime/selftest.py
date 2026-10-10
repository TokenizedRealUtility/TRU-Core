#!/usr/bin/env python3
"""Offline tests: temporary files + fake loopback provider; no real model/Core."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import tru_agent

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.base = Path(self.t.name)
        self.home = self.base/'runtime'
        self.manifest = self.base/'manifest.json'
        self.manifest.write_text(json.dumps({'schema':'TRU_AGENT_MANIFEST_V1', 'name':'Test',
            'token_id':'a'*16,'issuance_txid':'b'*64,'issuing_address':'TestIssuer',
            'network_genesis':tru_agent.GENESIS,'avatar_url':'https://example.net/avatar.png'}))
        self.manifest.chmod(0o600)
        self.endpoint = 'http://127.0.0.1:5051/v1/chat/completions'
    def tearDown(self): self.t.cleanup()
    def runcli(self, *args, ok=True):
        r = subprocess.run([sys.executable, str(Path(__file__).with_name('tru_agent.py')),
             '--home', str(self.home), *args], capture_output=True, text=True)
        if ok: self.assertEqual(r.returncode,0,r.stderr)
        else: self.assertNotEqual(r.returncode,0,r.stdout)
        return r
    def init(self): self.runcli('init','--manifest',str(self.manifest),'--endpoint',self.endpoint)
    def test_restart_memory(self):
        self.init(); self.runcli('remember','Test phrase: copper moon 37')
        r = self.runcli('memories'); self.assertIn('copper moon 37',r.stdout)
        s=json.loads(self.runcli('status').stdout);self.assertEqual(s['memory_revision'],1)
    def test_duplicate_and_forget(self):
        self.init(); self.runcli('remember','one');self.runcli('remember','one')
        self.assertEqual(len(json.loads(self.runcli('memories').stdout)),1)
        self.runcli('forget','1');self.assertEqual(json.loads(self.runcli('memories').stdout),[])
    def test_checkpoint_tamper(self):
        self.init();self.runcli('remember','private test')
        self.runcli('checkpoint');p=next((self.home/'checkpoints').glob('*.json'))
        self.runcli('verify-checkpoint',str(p));p.write_bytes(p.read_bytes()+b' ')
        self.runcli('verify-checkpoint',str(p),ok=False)
    def test_identity_tamper(self):
        self.init();p=self.home/'identity-manifest.json';p.write_bytes(p.read_bytes()+b' ')
        self.runcli('status',ok=False)
    def test_no_overwrite(self):
        self.init();self.runcli('remember','keep');self.runcli('init','--manifest',str(self.manifest),ok=False)
        self.assertIn('keep',self.runcli('memories').stdout)
    def test_permissions(self):
        self.init()
        for n in ('config.json','identity-manifest.json','state.sqlite3','runtime.lock'):
            self.assertEqual((self.home/n).stat().st_mode & 0o777,0o600)
        self.assertEqual(self.home.stat().st_mode & 0o777,0o700)
    def test_symlink(self):
        real=self.base/'real';real.mkdir();self.home.symlink_to(real,target_is_directory=True)
        self.runcli('init','--manifest',str(self.manifest),ok=False)
    def test_bad_endpoint_and_markdown(self):
        for url in ('http://example.net:5051/v1/chat/completions','http://127.0.0.1:21832/rpc'):
            with self.assertRaises(ValueError):tru_agent.endpoint_check(url)
        m=json.loads(self.manifest.read_text());m['avatar_url']='[https://example.net/a](https://example.net/a)'
        self.manifest.write_text(json.dumps(m));self.runcli('init','--manifest',str(self.manifest),ok=False)
    def test_fake_provider_memory_and_error(self):
        seen=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));seen.append(body)
                if body['messages'][-1]['content']=='FAIL':
                    self.send_response(503);self.end_headers();return
                result={'choices':[{'message':{'content':'copper moon 37'}}]}
                self.send_response(200);self.end_headers();self.wfile.write(json.dumps(result).encode())
        server=http.server.HTTPServer(('127.0.0.1',0),Handler)
        th=threading.Thread(target=server.serve_forever,daemon=True);th.start()
        try:
            self.endpoint=f'http://127.0.0.1:{server.server_port}/v1/chat/completions';self.init()
            self.runcli('remember','Test phrase: copper moon 37')
            self.runcli('ask','What is my test phrase?')
            self.assertIn('copper moon 37',seen[-1]['messages'][0]['content'])
            self.runcli('clear-chat');self.runcli('ask','Repeat my test phrase')
            self.assertEqual(len(seen[-1]['messages']),2)
            self.assertIn('copper moon 37',seen[-1]['messages'][0]['content'])
            before=json.loads(self.runcli('status').stdout)['chat_messages']
            self.runcli('ask','FAIL',ok=False)
            self.assertEqual(json.loads(self.runcli('status').stdout)['chat_messages'],before)
        finally:server.shutdown();server.server_close();th.join()
    def test_repository_refusal(self):
        (self.base/'.git').mkdir()
        self.runcli('init','--manifest',str(self.manifest),ok=False)
        self.assertFalse(self.home.exists())
    def test_home_required(self):
        r=subprocess.run([sys.executable,str(Path(__file__).with_name('tru_agent.py')),'status'],capture_output=True)
        self.assertNotEqual(r.returncode,0)
    def test_lock(self):
        self.init()
        with tru_agent.locked(self.home):self.runcli('status',ok=False)

if __name__=='__main__':unittest.main(verbosity=2)

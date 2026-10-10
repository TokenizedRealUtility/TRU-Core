import contextlib,copy,io,json,os,tempfile,unittest,sys
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import tru_agent as rt
import tru_agent_auto as auto
import tru_agent_anchor as anchor
import tru_agent_providers as providers

class ProviderTests(unittest.TestCase):
 def test_all_wire_formats(self):
  messages=[{'role':'system','content':'system'},{'role':'user','content':'hello'}]
  with patch.dict(os.environ,{'OPENAI_API_KEY':'o','XAI_API_KEY':'x','ANTHROPIC_API_KEY':'c'}):
   for provider in providers.PROVIDERS:
    endpoint='http://127.0.0.1:5051/v1/chat/completions' if provider=='custom' else None
    config=providers.settings(provider,endpoint,'chosen-model',allow_remote=True)
    c,h,p=providers.build(config,messages)
    self.assertFalse(p['stream']);self.assertNotIn('tools',p)
    if provider=='claude':
     self.assertEqual(p['system'],'system');self.assertEqual(h['x-api-key'],'c');response={'content':[{'type':'text','text':'ok'}]}
    elif provider=='ollama':response={'message':{'content':'ok'}}
    else:response={'choices':[{'message':{'content':'ok'}}]}
    self.assertEqual(providers.parse(provider,response),'ok')
    if provider=='openai':self.assertIn('max_completion_tokens',p)
 def test_remote_opt_in_and_http(self):
  with self.assertRaises(ValueError):providers.settings('openai',None,'model')
  for endpoint in ['http://example.org/v1/chat/completions','https://user:secret@example.org/v1/chat/completions','https://example.org/v1/chat/completions?key=secret','[https://example.org](https://example.org)']:
   with self.assertRaises(ValueError):providers.settings('custom',endpoint,'model',allow_remote=True)
 def test_missing_key_and_official_endpoint(self):
  c=providers.settings('openai',None,'model',allow_remote=True)
  with patch.dict(os.environ,{},clear=True):
   with self.assertRaises(ValueError):providers.build(c,[{'role':'system','content':'x'}])
  with self.assertRaises(ValueError):providers.settings('claude','https://evil.example/v1/messages','model',allow_remote=True)
 def test_old_config(self):
  self.assertEqual(providers.validate({'endpoint':'http://127.0.0.1:5051/v1/chat/completions','model':'nemotron'})['provider'],'nemotron')
 def test_response_errors(self):
  for provider in providers.PROVIDERS:
   with self.assertRaises(ValueError):providers.parse(provider,{'error':'bad'})
   with self.assertRaises(ValueError):providers.parse(provider,{})

class AutoTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)/'runtime';rt.private_dir(self.root)
  self.manifest={'schema':'TRU_AGENT_MANIFEST_V1','network_genesis':rt.GENESIS,'name':'Test','token_id':'a'*16,'issuance_txid':'b'*64,'issuing_address':'test-issuer','avatar_url':'https://example.org/image.png'}
  source=Path(self.tmp.name)/'manifest.json';rt.write_new(source,rt.canonical(self.manifest))
  with contextlib.redirect_stdout(io.StringIO()):rt.initialize(self.root,source,'http://127.0.0.1:5051/v1/chat/completions','nemotron')
  self.config,self.m,self.db=rt.load(self.root)
  with contextlib.redirect_stdout(io.StringIO()):
   rt.remember(self.db,'private original');self.checkpoint=rt.checkpoint(self.root,self.config,self.db)
  self.d=anchor.descriptor(rt,self.root,self.config,self.checkpoint)
  self.report=self.report_for(self.d)
  self.args=SimpleNamespace(checkpoint=str(self.checkpoint),core_cli='/fake/cli',policy_dir=str(Path(self.tmp.name)/'policy'),min_interval=60,max_per_day=2,budget_atoms=2000,expires_days=1,did='did:on_tru:test')
  with patch.object(anchor,'rpc',return_value=self.report),contextlib.redirect_stdout(io.StringIO()):auto.prepare(rt,self.root,self.config,self.m,self.args)
  self.policy=Path(self.args.policy_dir)/'policy.json'
 def tearDown(self):self.db.close();self.tmp.cleanup()
 def report_for(self,d):
  return {'tokenID':d['token_id'],'token_type':'NCFT','issuance_txid':'b'*64,'issuance_status':'CONFIRMED','require_confirmed':True,'runtime_ok':True,'history_ok':True,'all_anchor_payloads_valid':True,'all_anchor_txs_confirmed':True,'history':{'root_verified':True,'latest_epoch':2,'epochs':[{'epoch':2,'checkpoint':d,'record_format_version':5,'editor_authorization':'ISSUER_VERIFIED'}]},'anchors':[{'epoch':2,'checkpoint':d,'chain_status':'CONFIRMED','payload_valid':True,'txid':'e'*64}]}
 def enable(self):
  p=json.loads(self.policy.read_text());p['enabled']=True;p['agents'][0]['enabled']=True;auto.replace_private(rt,self.policy,rt.canonical(p))
 def change(self):
  with contextlib.redirect_stdout(io.StringIO()):rt.remember(self.db,'SECRET-MEMORY-NEVER-IN-INBOX')
 def runstep(self):
  with contextlib.redirect_stdout(io.StringIO()):
   auto.recover_publish(rt,self.root,self.config);auto.step(rt,self.root,self.config,self.db,'/fake/cli')
 def test_disabled_and_no_change(self):
  self.change();self.runstep();self.assertFalse((Path(self.args.policy_dir)/'inbox/request.json').exists())
 def test_enabled_unchanged(self):
  self.enable();self.runstep();self.assertFalse((Path(self.args.policy_dir)/'inbox/request.json').exists())
 def test_public_only_and_pending_retry(self):
  self.enable();self.change();self.runstep();inbox=Path(self.args.policy_dir)/'inbox/request.json';raw=inbox.read_bytes();e=json.loads(raw)
  self.assertNotIn(b'SECRET-MEMORY',raw);key=(Path(self.args.policy_dir)/'submission.key').read_text()
  self.assertEqual(e['hmac_sha256'],auto.mac(key,e['checkpoint']))
  # Crash after state persisted, before inbox publication: republish exact original request.
  inbox.unlink()
  with patch.object(anchor,'rpc',return_value={'runtime_ok':False}):self.runstep()
  self.assertEqual(inbox.read_bytes(),raw)
  self.assertIsNotNone(json.loads((self.root/'auto-state.json').read_text())['pending_checkpoint'])
  with patch.object(anchor,'rpc',return_value=self.report_for(e['checkpoint'])):self.runstep()
  state=json.loads((self.root/'auto-state.json').read_text());self.assertIsNone(state['pending_checkpoint']);self.assertEqual(state['completed_revision'],2)
  self.assertEqual(len(list((self.root/'anchor-receipts').glob('*.json'))),1)
 def test_no_reinitialize(self):
  with self.assertRaises(ValueError):auto.prepare(rt,self.root,self.config,self.m,self.args)
 def test_expired(self):
  self.enable();self.change();p=json.loads(self.policy.read_text());p['agents'][0]['expires_at_unix']=1;auto.replace_private(rt,self.policy,rt.canonical(p));self.runstep()
  self.assertFalse((Path(self.args.policy_dir)/'inbox/request.json').exists())
 def test_wrong_manifest(self):
  self.enable();self.change();p=json.loads(self.policy.read_text());p['agents'][0]['manifest_sha256']='f'*64;auto.replace_private(rt,self.policy,rt.canonical(p))
  with self.assertRaises(ValueError):self.runstep()
 def test_hmac_binding(self):
  key='a'*64;d={'token_id':'a'*16,'memory_revision':4};sig=auto.mac(key,d)
  d['memory_revision']=5;self.assertNotEqual(sig,auto.mac(key,d));self.assertNotEqual(sig,auto.mac('b'*64,d))

if __name__=='__main__':
 os.umask(0o077)
 unittest.main()

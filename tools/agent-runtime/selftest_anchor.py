import copy,importlib.util,json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import tru_agent as r
import tru_agent_anchor as a
class Tests(unittest.TestCase):
 def setUp(self):
  self.d={'schema':'TRU_AGENT_CHECKPOINT_REQUEST_V1','token_id':'a'*16,'checkpoint_sha256':'b'*64,'manifest_sha256':'c'*64,'memory_revision':3,'checkpoint_bytes':999,'scope':'explicit_memories_only'}
  self.report={'tokenID':'a'*16,'token_type':'NCFT','issuance_txid':'d'*64,'issuance_status':'CONFIRMED','require_confirmed':True,'runtime_ok':True,'history_ok':True,'all_anchor_payloads_valid':True,'all_anchor_txs_confirmed':True,'history':{'root_verified':True,'epochs':[{'epoch':2,'checkpoint':self.d,'record_format_version':5,'editor_authorization':'ISSUER_VERIFIED'}]},'anchors':[{'epoch':2,'checkpoint':self.d,'chain_status':'CONFIRMED','payload_valid':True,'txid':'e'*64}]}
 def test_confirmed(self):self.assertEqual(a.confirmed(self.report,self.d,'d'*64)['epoch'],2)
 def test_fail_closed(self):
  for key in ['runtime_ok','history_ok','all_anchor_payloads_valid','all_anchor_txs_confirmed','require_confirmed']:
   x=copy.deepcopy(self.report);x[key]=False
   with self.assertRaises(ValueError):a.confirmed(x,self.d,'d'*64)
  for field,value in [('checkpoint',{}),('chain_status','MEMPOOL'),('payload_valid',False)]:
   x=copy.deepcopy(self.report);x['anchors'][0][field]=value
   with self.assertRaises(ValueError):a.confirmed(x,self.d,'d'*64)
 def test_wrong_issuer(self):
  x=copy.deepcopy(self.report);x['history']['epochs'][0]['editor_authorization']='LEGACY_UNAUTHENTICATED'
  with self.assertRaises(ValueError):a.confirmed(x,self.d,'d'*64)
 def test_duplicate(self):
  x=copy.deepcopy(self.report);x['anchors']*=2
  with self.assertRaises(ValueError):a.confirmed(x,self.d,'d'*64)
 def test_private_bytes_excluded(self):
  with tempfile.TemporaryDirectory() as t:
   root=Path(t);c={'token_id':'a'*16,'manifest_sha256':'c'*64}
   v={'schema':'TRU_AGENT_LOCAL_CHECKPOINT_V1','token_id':'a'*16,'manifest_sha256':'c'*64,'memory_revision':3,'scope':'explicit_memories_only','facts':[{'text':'SECRET-NOT-PUBLIC'}]}
   raw=r.canonical(v);path=root/(r.sha(raw)+'.json');path.write_bytes(raw);path.chmod(0o600)
   a.request(r,root,c,path);a.request(r,root,c,path)
   d=json.loads(next((root/'anchor-requests').glob('*.json')).read_text());self.assertEqual(len(d),7);self.assertNotIn('SECRET-NOT-PUBLIC',json.dumps(d))
   path.write_bytes(raw+b' ')
   with self.assertRaises(ValueError):a.descriptor(r,root,c,path)
if __name__=='__main__':unittest.main()

"""Local checkpoint scheduler/handoff. Core enforces authority and fee budgets."""
import hashlib,hmac,json,os,secrets,time
from pathlib import Path
import tru_agent_anchor as anchor
GENESIS='b62fba2600030d97a06916b17694bec8d97ca14c1db682b2e57b424bd6000000'

def replace_private(rt,path,data):
 import tempfile
 rt.safe_file(path)
 fd,name=tempfile.mkstemp(prefix='.auto-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.replace(name,path)
  d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(d)
  finally:os.close(d)
 finally:
  if os.path.exists(name):os.unlink(name)

def mac(key,d):
 message='TRU-AGENT-CHECKPOINT-AUTO-V1\n'+GENESIS+'\n'+json.dumps(d,sort_keys=True,separators=(',',':'),ensure_ascii=False)
 return hmac.new(key.encode(),message.encode(),hashlib.sha256).hexdigest()

def prepare(rt,root,config,manifest,args):
 # All outputs private; nothing enabled, signed, or sent to Core.
 if (root/'auto-config.json').exists():raise ValueError('Automation already prepared; preserve existing state and policy')
 d=anchor.descriptor(rt,root,config,args.checkpoint)
 report=anchor.rpc(args.core_cli,'verifytokenevolution',{'tokenID':config['token_id'],'require_confirmed':True})
 a=anchor.confirmed(report,d,manifest['issuance_txid'])
 if a['epoch']!=report['history']['latest_epoch']:raise ValueError('Use the latest confirmed checkpoint as baseline')
 if not 60<=args.min_interval<=31536000 or not 1<=args.max_per_day<=1000 or not 1000<=args.budget_atoms<=10**12 or not 1<=args.expires_days<=365:raise ValueError('Invalid finite policy limits')
 directory=Path(args.policy_dir).expanduser().absolute()
 for parent in (directory,*directory.parents):
  if (parent/'.git').exists() or ((parent/'CMakeLists.txt').exists() and (parent/'src').is_dir()):raise ValueError('Keep policy and credentials outside repositories')
 rt.private_dir(directory)
 keyfile=directory/'submission.key';policyfile=directory/'policy.json';inbox=directory/'inbox'
 if any(p.exists() for p in (keyfile,policyfile,inbox)):raise ValueError('Choose a fresh policy directory; no overwrite')
 rt.private_dir(inbox)
 key=secrets.token_hex(32);rt.write_new(keyfile,key.encode())
 policy={'enabled':False,'network_genesis':GENESIS,'token_id':config['token_id'],
  'issuer':manifest['issuing_address'],'issuance_txid':manifest['issuance_txid'],
  'manifest_sha256':config['manifest_sha256'],'label':manifest['name'],
  'did':manifest.get('meta_id',args.did or ''),'credential_file':str(keyfile),'inbox':str(inbox),
  'baseline_epoch':a['epoch'],'expires_at_unix':int(time.time())+args.expires_days*86400,
  'min_interval_seconds':args.min_interval,'max_per_day':args.max_per_day,
  'max_fee_atoms':1000,'total_budget_atoms':args.budget_atoms}
 rt.write_new(policyfile,rt.canonical({'schema':'TRU_AGENT_AUTO_POLICY_V1','enabled':False,'agents':[policy]}))
 rt.write_new(root/'auto-config.json',rt.canonical({'schema':'TRU_AGENT_AUTO_LOCAL_V1','policy_file':str(policyfile),'inbox':str(inbox),'credential_file':str(keyfile)}))
 rt.write_new(root/'auto-state.json',rt.canonical({'completed_revision':d['memory_revision'],'pending_checkpoint':None,'last_receipt_check':0}))
 print('AUTOMATION_PREPARED_DISABLED')
 print('POLICY_FILE='+str(policyfile))
 print('Review policy, enable its root and agent flags, and configure [agent_checkpoint] in Core.')
 print('DID is a label only. No wallet keys or signing authority are stored in this runtime.')

def step(rt,root,config,db,cli):
 for p in ('auto-config.json','auto-state.json'):rt.safe_file(root/p)
 local=json.loads((root/'auto-config.json').read_text());state=json.loads((root/'auto-state.json').read_text())
 rt.safe_file(Path(local['policy_file']))
 policy=json.loads(Path(local['policy_file']).read_text())
 matches=[p for p in policy['agents'] if p['token_id']==config['token_id']]
 if len(matches)!=1:raise ValueError('No unique policy for this token')
 p=matches[0]
 # Always allow read-only confirmation recovery, including after policy revocation.
 pending=state['pending_checkpoint']
 if pending:
  pending=Path(pending)
  try:anchor.verify(rt,root,config,pending,cli)
  except (ValueError,OSError) as e:
   print('ANCHOR_PENDING_OR_UNVERIFIED:',e)
   return
  d=anchor.descriptor(rt,root,config,pending)
  state.update(completed_revision=d['memory_revision'],pending_checkpoint=None,last_receipt_check=int(time.time()))
  replace_private(rt,root/'auto-state.json',rt.canonical(state))
  print('AUTO_CHECKPOINT_COMPLETE')
  return
 if not policy.get('enabled') or not p.get('enabled'):print('AUTO_POLICY_DISABLED');return
 if int(time.time())>=p['expires_at_unix']:print('AUTO_POLICY_EXPIRED');return
 rev=rt.revision(db)
 if rev<state['completed_revision']:raise ValueError('Memory revision moved backwards; restore/review runtime')
 if rev==state['completed_revision']:print('AUTO_NO_MEMORY_CHANGE');return
 # Export complete private snapshot before publishing one immutable request.
 checkpoint=rt.checkpoint(root,config,db)
 d=anchor.descriptor(rt,root,config,checkpoint)
 if d['manifest_sha256']!=p['manifest_sha256']:raise ValueError('Manifest is not authorized')
 rt.safe_file(Path(local['credential_file']));key=Path(local['credential_file']).read_text()
 if len(key)!=64 or any(c not in '0123456789abcdef' for c in key):raise ValueError('Invalid submission credential')
 envelope={'checkpoint':d,'hmac_sha256':mac(key,d)}
 state['pending_checkpoint']=str(checkpoint)
 # Preserve the exact request before handoff; crash recovery republishes the same bytes.
 replace_private(rt,root/'auto-pending-request.json',rt.canonical(envelope))
 replace_private(rt,root/'auto-state.json',rt.canonical(state))
 rt.private_dir(Path(local['inbox']))
 replace_private(rt,Path(local['inbox'])/'request.json',rt.canonical(envelope))
 print('AUTO_REQUEST_EXPORTED; Core policy approval and confirmation still required')

def recover_publish(rt,root,config):
 # Called each step before verification so a crash before initial publish is retryable.
 statefile=root/'auto-state.json'
 if not statefile.exists():return
 rt.safe_file(statefile);state=json.loads(statefile.read_text())
 if not state.get('pending_checkpoint'):return
 for n in ('auto-config.json','auto-pending-request.json'):rt.safe_file(root/n)
 local=json.loads((root/'auto-config.json').read_text())
 envelope=json.loads((root/'auto-pending-request.json').read_text())
 d=anchor.descriptor(rt,root,config,state['pending_checkpoint'])
 if envelope['checkpoint']!=d:raise ValueError('Pending request/checkpoint mismatch')
 rt.private_dir(Path(local['inbox']))
 replace_private(rt,Path(local['inbox'])/'request.json',rt.canonical(envelope))

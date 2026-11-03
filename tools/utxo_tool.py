#!/usr/bin/env python3
"""Core CLI helper. Dry preview by default; only --execute submits real self-transfers."""
import argparse,json,os,subprocess,sys,time,tempfile
from decimal import Decimal,InvalidOperation
from pathlib import Path

def atoms(text):
 try:
  d=Decimal(text)*100000000
  if not d.is_finite() or d!=d.to_integral_value() or d<=0:raise ValueError()
  return int(d)
 except (ValueError,InvalidOperation):raise ValueError('Use a positive decimal amount with at most eight fractional digits')
def rpc(cli,action,p):
 r=subprocess.run([str(cli),'-timeout=120','utxo',action,json.dumps(p,separators=(',',':'))],capture_output=True,text=True,timeout=135)
 if r.returncode:raise RuntimeError('Core rejected or transport failed; inspect the journal/txid before retrying. '+r.stderr[:500]+r.stdout[:500])
 result=json.loads(r.stdout)
 if not isinstance(result,dict) or result.get('error'):raise RuntimeError('Unexpected Core response')
 return result
def submit(cli,plan):
 result=rpc(cli,'submit',{'plan':plan,'confirm':'SUBMIT'})
 if result.get('accepted') is not True or result.get('broadcast') is not True or result.get('txid')!=plan.get('txid'):
  raise RuntimeError('Uncertain submission response: inspect the journal transaction ID; do not resubmit blindly')
 return result
def save(path,value,exclusive=False):
 data=(json.dumps(value,indent=2)+'\n').encode()
 if path.is_symlink():raise ValueError('Refusing symlink journal/plan')
 if exclusive:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 else:
  fd,tmp=tempfile.mkstemp(prefix='.utxo-journal-',dir=path.parent)
  try:
   with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
   os.replace(tmp,path)
  finally:
   if os.path.exists(tmp):os.unlink(tmp)
 if os.name=='posix':
  fd=os.open(path.parent,os.O_RDONLY)
  try:os.fsync(fd)
  finally:os.close(fd)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cli',required=True,type=Path)
 sub=p.add_subparsers(dest='command',required=True)
 sub.add_parser('list')
 for name in ('split','consolidate','run'):
  a=sub.add_parser(name);a.add_argument('--address',required=True);a.add_argument('--max-fee',default='0.001');a.add_argument('--inputs',type=Path,help='JSON array of explicit txid/vout objects; omitted = automatic selection')
  if name!='consolidate':a.add_argument('--count',type=int,default=2);a.add_argument('--amount',default='0.01')
  if name=='run':
   a.add_argument('--rounds',type=int,default=3);a.add_argument('--total-fee-budget',default='0.003');a.add_argument('--confirmation-timeout',type=int,default=1800);a.add_argument('--execute',action='store_true');a.add_argument('--journal',type=Path,required=True)
  else:a.add_argument('--out',type=Path,required=True,help='New preview file; never broadcast')
 a=sub.add_parser('submit');a.add_argument('--plan',required=True,type=Path);a.add_argument('--journal',required=True,type=Path);a.add_argument('--execute',action='store_true')
 q=p.parse_args();cli=q.cli.resolve()
 if q.command=='list':print(json.dumps(rpc(cli,'list',{}),indent=2));return
 if q.command=='submit':
  plan=json.loads(q.plan.read_text());print(json.dumps(plan,indent=2))
  if not q.execute:print('PREVIEW ONLY: add --execute to submit the reviewed plan');return
  record={'state':'submission_intent','plan':plan};save(q.journal,record,True)
  record['result']=submit(cli,plan);record['state']='accepted';save(q.journal,record);print(json.dumps(record['result'],indent=2));return
 cap=atoms(q.max_fee)
 req={'mode':'consolidate' if q.command=='consolidate' else 'split','address':q.address,'max_fee':q.max_fee}
 if q.command!='consolidate':req.update(count=q.count,amount=q.amount);atoms(q.amount)
 if q.inputs:req['inputs']=json.loads(q.inputs.read_text())
 if q.command!='run':
  plan=rpc(cli,'prepare',req);save(q.out,plan,True);print(json.dumps(plan,indent=2));print('PREVIEW SAVED; no broadcast');return
 if not 1<=q.rounds<=20:raise ValueError('rounds must be 1..20')
 if not 30<=q.confirmation_timeout<=86400:raise ValueError('confirmation timeout must be 30..86400 seconds')
 budget=atoms(q.total_fee_budget)
 if cap*q.rounds>budget:raise ValueError('rounds * max-fee exceeds total-fee-budget')
 if q.inputs and q.rounds>1:raise ValueError('Explicit inputs support one round only; they cannot be reused')
 if not q.execute:
  print(json.dumps(rpc(cli,'prepare',req),indent=2));print('PREVIEW ONLY: no journal or transactions created');return
 record={'state':'running','test_activity':True,'rounds':[],'fee_budget_atoms':budget};save(q.journal,record,True)
 for i in range(q.rounds):
  plan=rpc(cli,'prepare',req)
  if sum(x['plan']['fee_atoms'] for x in record['rounds'])+plan['fee_atoms']>budget:raise ValueError('Fee budget exceeded')
  step={'round':i+1,'state':'submission_intent','plan':plan};record['rounds'].append(step);save(q.journal,record)
  # A timeout leaves submission_intent on disk. No automatic resubmission.
  step['result']=submit(cli,plan);step['state']='accepted';save(q.journal,record)
  print('ACCEPTED',plan['txid'],flush=True);deadline=time.monotonic()+q.confirmation_timeout
  while time.monotonic()<deadline:
   inv=rpc(cli,'list',{})
   if any(u['txid']==plan['txid'] and u['eligible'] for u in inv['utxos']):break
   time.sleep(10)
  else:raise RuntimeError('Confirmation timeout: stopped; inspect journal before further sends')
  step['state']='confirmed_output_observed';save(q.journal,record)
 record['state']='complete';save(q.journal,record);print('COMPLETE: labeled self-transfer test; see journal')
if __name__=='__main__':
 try:main()
 except Exception as e:print('STOPPED: '+str(e),file=sys.stderr);sys.exit(1)

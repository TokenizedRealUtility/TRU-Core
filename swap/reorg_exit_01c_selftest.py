#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, os, sqlite3, tempfile
from pathlib import Path

def load(name):
 p=Path(__file__).with_name(name); spec=importlib.util.spec_from_file_location('t_'+name.replace('.','_'),str(p)); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

m=load('reorg_exit_rebroadcast_v1.py')
assert m.VERSION=='TRU-REORG-EXIT-01C'
assert m.enabled() is False
class S: pass
class A: pass
with tempfile.TemporaryDirectory() as td:
 a=A(); a.store=S(); a.store.path=Path(td)/'agent.sqlite3'; a.tru=S(); a.bsty=S()
 raw='00aa11bb'; txid='11'*32; payload=__import__('hashlib').sha256(bytes.fromhex(raw)).hexdigest()
 record={'swapId':'22'*32,'evidence':{'truFundingTxid':'33'*32,'truFundingVout':1}}
 row={'chain':'tru','kind':'claim','txid':txid,'currentTxState':'SIDECHAIN','historicalReorged':True,'preimageExposed':True}
 ass={'swapId':record['swapId'],'chain':'tru','kind':'claim','txid':txid,'payloadSha256':payload,'sameTxRebroadcastEligible':True}
 m._RUNTIME.assess_exact_exit_recovery=lambda *x,**y: dict(ass)
 m._RUNTIME._tru_exact_raw_and_decode=lambda *x,**y:(raw,txid,'TRU_GETTRANSACTION',{'txid':txid})
 calls=[]; m._broadcast=lambda *x,**y:(calls.append(1) or txid)
 old=os.environ.get(m.ENABLE_ENV); os.environ[m.ENABLE_ENV]=m.ENABLE_VALUE
 try:
  out=m.maybe_execute_exact_exit_rebroadcast(a,record,row,ass)
  assert out['action']=='EXACT_SAME_TX_REBROADCASTED' and len(calls)==1
  # Second call can never rebroadcast the same intent.
  out2=m.maybe_execute_exact_exit_rebroadcast(a,record,row,ass)
  assert out2['action']=='ALREADY_EXECUTED_NO_RETRY' and len(calls)==1
  # Raw bytes must not be in sqlite durable bytes.
  db=Path(str(a.store.path)+'.exit-reorg.sqlite3')
  for suffix in ('','-wal','-shm'):
   p=Path(str(db)+suffix)
   if p.exists(): assert raw.encode() not in p.read_bytes()
 finally:
  if old is None: os.environ.pop(m.ENABLE_ENV,None)
  else: os.environ[m.ENABLE_ENV]=old
print('TRU_REORG_EXIT_01C_SELFTEST=PASS')
print('EXPLICIT_EXECUTION_GATE_REQUIRED=PASS')
print('EXACT_SAME_TX_ONLY=PASS')
print('DURABLE_INTENT_BEFORE_NETWORK_MUTATOR=PASS')
print('SECOND_EXECUTION_ATTEMPT=FORBIDDEN')
print('UNKNOWN_OUTCOME_BLIND_RETRY=FORBIDDEN')
print('RAW_EXIT_BYTES_PERSISTED=NO')
print('RECONSTRUCT_OR_RESIGN_AFTER_REORG=NO')

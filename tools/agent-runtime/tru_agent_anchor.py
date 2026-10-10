"""Exact public checkpoint handoff; read-only Core RPC and durable local receipts."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


def descriptor(runtime, root, config, checkpoint):
    checkpoint=Path(checkpoint).expanduser()
    runtime.safe_file(checkpoint)
    if checkpoint.stat().st_size > 1048576:
        raise ValueError('Checkpoint exceeds 1 MiB')
    raw=checkpoint.read_bytes();data=json.loads(raw)
    digest=hashlib.sha256(raw).hexdigest()
    if (checkpoint.stem!=digest or data.get('schema')!='TRU_AGENT_LOCAL_CHECKPOINT_V1'
            or data.get('token_id')!=config['token_id']
            or data.get('manifest_sha256')!=config['manifest_sha256']
            or data.get('scope')!='explicit_memories_only'
            or type(data.get('memory_revision')) is not int
            or not 0<data['memory_revision']<2**64):
        raise ValueError('Invalid checkpoint identity, revision, scope or exact-byte hash')
    return {'schema':'TRU_AGENT_CHECKPOINT_REQUEST_V1','token_id':config['token_id'],
            'checkpoint_sha256':digest,'manifest_sha256':config['manifest_sha256'],
            'memory_revision':data['memory_revision'],'checkpoint_bytes':len(raw),
            'scope':'explicit_memories_only'}


def request(runtime, root, config, checkpoint):
    d=descriptor(runtime,root,config,checkpoint)
    folder=runtime.private_dir(root/'anchor-requests')
    path=folder/(d['checkpoint_sha256']+'.request.json')
    raw=runtime.canonical(d)
    if path.exists():
        runtime.safe_file(path)
        if path.read_bytes()!=raw:raise ValueError('Existing request differs; preserve for inspection')
    else:runtime.write_new(path,raw)
    print('PUBLIC_REQUEST_FILE='+str(path))
    print(json.dumps(d,indent=2))
    print('In Core: 17 > 2 > 7, import this request; 2 commits after exact digest and COMMIT approval.')
    print('No RPC submission, wallet access, or private memory disclosure performed.')


def rpc(cli, method, params):
    p=subprocess.run([str(cli),'raw',method,json.dumps(params)],capture_output=True,text=True,timeout=60,check=True)
    r=json.loads(p.stdout)
    if not isinstance(r,dict):raise ValueError('Unexpected Core RPC response')
    if r.get('error'):raise ValueError('Core RPC error: '+str(r['error']))
    r=r.get('result',r)
    if not isinstance(r,dict):raise ValueError('Unexpected Core result')
    return r


def confirmed(report,d,issuance):
    if (report.get('tokenID')!=d['token_id'] or report.get('token_type')!='NCFT'
            or report.get('issuance_txid')!=issuance or report.get('issuance_status')!='CONFIRMED'
            or report.get('require_confirmed') is not True
            or report.get('runtime_ok') is not True or report.get('history_ok') is not True
            or report.get('all_anchor_payloads_valid') is not True
            or report.get('all_anchor_txs_confirmed') is not True):
        raise ValueError('Core has not confirmed and verified the complete provenance history. Wait or inspect Core; do not recommit.')
    history=report.get('history',{})
    if history.get('root_verified') is not True:raise ValueError('Issuance root not verified')
    matches=[a for a in report.get('anchors',[]) if a.get('checkpoint')==d]
    if len(matches)!=1:raise ValueError('No unique exact checkpoint commitment found. No confirmation claimed.')
    a=matches[0]
    if a.get('chain_status')!='CONFIRMED' or a.get('payload_valid') is not True or not re.fullmatch('[0-9a-f]{64}',a.get('txid','')):
        raise ValueError('Exact checkpoint anchor is not confirmed with valid payload')
    epochs=[e for e in history.get('epochs',[]) if e.get('epoch')==a.get('epoch')]
    if (len(epochs)!=1 or epochs[0].get('checkpoint')!=d
            or epochs[0].get('record_format_version')!=5
            or epochs[0].get('editor_authorization')!='ISSUER_VERIFIED'):
        raise ValueError('Exact checkpoint lacks verified V5 issuer authorization')
    return a


def verify(runtime,root,config,checkpoint,cli):
    d=descriptor(runtime,root,config,checkpoint)
    manifest=json.loads((root/'identity-manifest.json').read_text())
    report=rpc(Path(cli).expanduser(),'verifytokenevolution',{'tokenID':config['token_id'],'require_confirmed':True})
    a=confirmed(report,d,manifest['issuance_txid'])
    receipt={'schema':'TRU_AGENT_CHECKPOINT_RECEIPT_V1','checkpoint':d,'epoch':a['epoch'],
             'anchor_txid':a['txid'],'verified_at_unix':int(time.time()),
             'verification_source':'configured Core CLI, not independent light-client proof','core_report':report}
    folder=runtime.private_dir(root/'anchor-receipts')
    path=folder/(d['checkpoint_sha256']+'-'+str(time.time_ns())+'.json')
    runtime.write_new(path,runtime.canonical(receipt))
    print('CHECKPOINT_ANCHOR_CONFIRMED=YES')
    print('ISSUER_AUTHORIZATION=VERIFIED')
    print('ANCHOR_TXID='+a['txid'])
    print('RECEIPT_FILE='+str(path))

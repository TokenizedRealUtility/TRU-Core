#!/usr/bin/env python3
"""TRU DataFeed v1: local journal, TRUSCRIPT OP_RETURN publication, readback.
Uses installed tru-cli and the node wallet, never handles wallet private keys.
"""
import argparse,csv,hashlib,json,os,sqlite3,subprocess,sys,time,pathlib
from datetime import datetime,timezone

PREFIX='TRUDF1:'
def canonical(x): return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def sha(x): return hashlib.sha256(x.encode('utf8')).hexdigest()
def iso(): return datetime.now(timezone.utc).isoformat()
def dbopen(path):
    p=pathlib.Path(path).expanduser();p.parent.mkdir(parents=True,exist_ok=True);os.chmod(p.parent,0o700)
    db=sqlite3.connect(p)
    db.execute('CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY,feed TEXT NOT NULL,kind TEXT NOT NULL,body TEXT NOT NULL,hash TEXT NOT NULL,txid TEXT,status TEXT NOT NULL,created TEXT NOT NULL)')
    db.commit();os.chmod(p,0o600);return db

def rpc(args,method,params):
    cmd=[args.cli,'-json','raw',method,canonical(params)]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=90)
    if p.returncode:raise RuntimeError('RPC '+method+' failed: '+p.stderr.strip()[:400])
    try: data=json.loads(p.stdout)
    except ValueError:raise RuntimeError('Could not parse JSON for '+method+': '+p.stdout[:160])
    if isinstance(data,dict) and data.get('error'):raise RuntimeError('RPC '+method+': '+str(data['error'])[:400])
    # tru-cli -json prints result directly (or some builds full envelope).
    if isinstance(data,dict) and data.get('jsonrpc')=='2.0':return data.get('result')
    return data

def input_records(args):
    if args.record is not None: yield json.loads(args.record);return
    if args.file:
        path=pathlib.Path(args.file)
        if path.suffix.lower()=='.csv':
            with path.open(newline='',encoding='utf8') as f:
                yield from csv.DictReader(f)
        elif path.suffix.lower()=='.json':
            with path.open(encoding='utf8') as f:data=json.load(f)
            yield from (data if isinstance(data,list) else [data])
        else:
            with path.open(encoding='utf8') as f:
                for line in f:
                    if line.strip():yield json.loads(line)
    else:
        for line in sys.stdin:
            if line.strip():yield json.loads(line)

def store(db,feed,rec):
    body=canonical(rec);h=sha(body)
    db.execute('INSERT INTO records (feed,kind,body,hash,status,created) VALUES (?,?,?,?,?,?)',(feed,'record',body,h,'QUEUED',iso()))

def select(db,feed,n):
    return db.execute("SELECT id,body,hash FROM records WHERE feed=? AND status='QUEUED' ORDER BY id LIMIT ?",(feed,n)).fetchall()

def publish(args,db,rows):
    if not rows:return
    ids=[r[0] for r in rows]; bodies=[json.loads(r[1]) for r in rows]
    block=canonical(bodies)
    digest=sha(block)
    envelope={'v':1,'f':args.feed,'n':len(rows),'h':digest,'m':args.mode}
    if args.mode=='inline':envelope['r']=bodies
    payload=PREFIX+canonical(envelope)
    length=len(payload.encode('utf8'))
    print('BATCH records=',len(rows),'bytes=',length,'sha256=',digest)
    if length>args.max_bytes:raise RuntimeError('Data too large ('+str(length)+' bytes); use --mode hash or smaller batch')
    if not args.broadcast:
        print('DRY_RUN=YES; BROADCAST=NO; use --broadcast with explicit --owner to sign and publish')
        return
    if not args.owner:raise RuntimeError('--owner required for broadcasting')
    # Persist intent before RPC to avoid blindly paying again after timeout.
    marks=','.join('?' for _ in ids)
    db.execute('UPDATE records SET status=? WHERE id IN ('+marks+')', ['SUBMITTING']+ids);db.commit()
    try:
        res=rpc(args,'inscribeTRUScript',{'data':payload,'owner':args.owner})
        txid=res.get('txid') if isinstance(res,dict) else None
        if not isinstance(txid,str) or len(txid)!=64:raise RuntimeError('Unexpected inscription response: '+repr(res)[:150])
    except Exception:
        # SUBMITTING indicates ambiguous outcome. Manual reconciliation required.
        print('SUBMISSION_UNCERTAIN=YES; do not retry before checking Core history',file=sys.stderr)
        raise
    db.execute('UPDATE records SET status=?,txid=? WHERE id IN ('+marks+')', ['OBSERVED',txid]+ids);db.commit()
    print('TXID='+txid+'; STATUS=OBSERVED (not yet confirmed)')

def lookup(args,txid):
    result=rpc(args,'gettransaction',{'txid':txid})
    if not isinstance(result,dict):raise RuntimeError('unexpected transaction status')
    details=rpc(args,'getTRUScriptDetails',{'txid':txid})
    if not isinstance(details,dict):raise RuntimeError('unexpected inscription details')
    payload=details.get('data','')
    if not isinstance(payload,str) or not payload.startswith(PREFIX):raise RuntimeError('not a TRUDF1 record')
    env=json.loads(payload[len(PREFIX):]);
    if env.get('v')!=1:raise RuntimeError('unsupported feed format')
    if env.get('m')=='inline':
        body=env.get('r'); verified=isinstance(body,list) and len(body)==env.get('n') and sha(canonical(body))==env.get('h')
    else:body=None;verified=None
    confirmed=result.get('txState')=='CONFIRMED' and result.get('active') is True and result.get('confirmations',0)>=1
    return {'txid':txid,'feed':env.get('f'),'count':env.get('n'),'mode':env.get('m'),'hash':env.get('h'), 'records':body,'inline_hash_valid':verified,'chain_confirmed':confirmed,'confirmations':result.get('confirmations',0),'source':'Core TRUSCRIPT local index + chain transaction status'}

def main():
    p=argparse.ArgumentParser(description='TRU DataFeed v1 — signed TRUSCRIPT-backed OP_RETURN publishing')
    p.add_argument('--cli',default=os.path.expanduser('~/NEW_TRU/build-native/bin/tru-cli'))
    p.add_argument('--db',default='~/.local/share/tru/datafeed-v1.sqlite3')
    s=p.add_subparsers(dest='cmd',required=True)
    add=s.add_parser('queue');add.add_argument('--feed',required=True);g=add.add_mutually_exclusive_group();g.add_argument('--record');g.add_argument('--file');add.add_argument('--stdin',action='store_true')
    pub=s.add_parser('publish');pub.add_argument('--feed',required=True);pub.add_argument('--owner');pub.add_argument('--mode',choices=['hash','inline'],default='hash');pub.add_argument('--batch-size',type=int,default=100);pub.add_argument('--max-bytes',type=int,default=512);pub.add_argument('--broadcast',action='store_true')
    get=s.add_parser('get');get.add_argument('txid');get.add_argument('--output')
    verify=s.add_parser('verify');verify.add_argument('txid');verify.add_argument('--file',help='JSON array of original records to compare with hash-mode batch')
    listing=s.add_parser('list');listing.add_argument('--feed')
    recover=s.add_parser('reconcile');recover.add_argument('--feed',required=True);recover.add_argument('--txid',required=True,help='manually identified txid after uncertain submission')
    args=p.parse_args();db=dbopen(args.db)
    if args.cmd=='queue':
        count=0
        with db:
            for rec in input_records(args):
                store(db,args.feed,rec);count+=1
        print('QUEUED='+str(count));return
    if args.cmd=='publish':
        if args.batch_size<1 or args.batch_size>10000 or args.max_bytes<100 or args.max_bytes>2048:raise RuntimeError('invalid batch-size/max-bytes')
        rows=select(db,args.feed,args.batch_size)
        if not rows:print('QUEUE_EMPTY=YES');return
        publish(args,db,rows);return
    if args.cmd in ('get','verify'):
        r=lookup(args,args.txid)
        if args.cmd=='verify':
            if args.file:
                with open(args.file,encoding='utf8') as f: records=json.load(f)
                r['provided_data_hash_valid']=sha(canonical(records))==r['hash']
            r['verified']=bool(r['chain_confirmed'] and (r['inline_hash_valid'] is True or r.get('provided_data_hash_valid') is True))
        text=json.dumps(r,indent=2,ensure_ascii=False)
        if getattr(args,'output',None):pathlib.Path(args.output).write_text(text+'\n',encoding='utf8')
        else:print(text)
        return
    if args.cmd=='list':
        query='SELECT id,feed,hash,txid,status,created FROM records'
        rows=db.execute(query+(' WHERE feed=?' if args.feed else '')+' ORDER BY id DESC LIMIT 1000',([args.feed] if args.feed else [])).fetchall()
        print(json.dumps([dict(zip(['id','feed','hash','txid','status','created'],r)) for r in rows],indent=2));return
    if args.cmd=='reconcile':
        r=lookup(args,args.txid)
        if r['feed']!=args.feed:raise RuntimeError('feed mismatch')
        # Never auto-clear ambiguous records: require operator investigation.
        print(json.dumps(r,indent=2));print('RECONCILE_READ_ONLY=YES; manual review required')

if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,OSError,sqlite3.Error) as e:print('ERROR:',e,file=sys.stderr);sys.exit(2)

#!/usr/bin/env python3
"""TRU DataFeed 0.08.1. Explicit publication; read-only discovery/watch.
No wallet keys, automatic rebroadcast, or consensus changes.
"""
import argparse,csv,hashlib,io,json,os,pathlib,re,sqlite3,subprocess,sys,time
from datetime import datetime,timezone
PREFIX='TRUDF1:'
MAX_PAYLOAD=254

def canonical(x): return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def sha(x): return hashlib.sha256(x.encode('utf8')).hexdigest()
def iso(): return datetime.now(timezone.utc).isoformat()
def ishash(x): return isinstance(x,str) and re.fullmatch('[0-9a-f]{64}',x) is not None

def unique_pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('Duplicate JSON key: '+key)
        result[key]=value
    return result

def parse(s):
    def bad(x):raise ValueError('Non-finite JSON number: '+x)
    return json.loads(s,object_pairs_hook=unique_pairs,parse_constant=bad)

class RPCError(RuntimeError):
    def __init__(self,method,code,message):
        self.code=code
        super().__init__(f'RPC {method}: code={code} message={message}')

def rpc(args,method,params):
    try:p=subprocess.run([os.path.expanduser(args.cli),'-json','raw',method,canonical(params)],capture_output=True,text=True,timeout=90)
    except subprocess.TimeoutExpired as e: raise RuntimeError('RPC '+method+' timed out; submission outcome may be unknown') from e
    try: data=parse(p.stdout)
    except ValueError as e: raise RuntimeError(f'RPC {method}: invalid JSON (exit {p.returncode}); '+p.stderr.strip()[:300]) from e
    if isinstance(data,dict) and data.get('error'):
        err=data['error'];raise RPCError(method,err.get('code') if isinstance(err,dict) else None,str(err.get('message',err) if isinstance(err,dict) else err)[:500])
    if p.returncode:raise RuntimeError(f'RPC {method} exited {p.returncode}: '+p.stderr.strip()[:300])
    return data.get('result') if isinstance(data,dict) and data.get('jsonrpc')=='2.0' else data

def private_db(path):
    p=pathlib.Path(path).expanduser().absolute()
    if p.is_symlink() or any(x.is_symlink() for x in p.parents):raise RuntimeError('Symlink database path refused')
    p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if not p.exists():
        fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
    if not p.is_file():raise RuntimeError('Database path must be a regular file')
    db=sqlite3.connect(p,timeout=20);db.execute('PRAGMA busy_timeout=20000');os.chmod(p,0o600)
    return db

def dbopen(path):
    db=private_db(path)
    db.execute('CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY,feed TEXT NOT NULL,kind TEXT NOT NULL,body TEXT NOT NULL,hash TEXT NOT NULL,txid TEXT,status TEXT NOT NULL,created TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS batches (id INTEGER PRIMARY KEY,feed TEXT NOT NULL,owner TEXT NOT NULL,payload TEXT NOT NULL,body TEXT NOT NULL,status TEXT NOT NULL,txid TEXT,created TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS batch_records (batch_id INTEGER NOT NULL,record_id INTEGER NOT NULL UNIQUE,PRIMARY KEY(batch_id,record_id))')
    db.commit();return db

def input_records(args):
    if args.record is not None:yield parse(args.record);return
    if args.file:
        p=pathlib.Path(args.file).expanduser()
        with p.open(encoding='utf8',newline='') as f:
            if p.suffix.lower()=='.csv':yield from csv.DictReader(f)
            elif p.suffix.lower()=='.json':
                x=parse(f.read());yield from (x if isinstance(x,list) else [x])
            else:
                for line in f:
                    if line.strip():yield parse(line)
    else:
        for line in sys.stdin:
            if line.strip():yield parse(line)

def store(db,feed,rec):
    body=canonical(rec)
    db.execute('INSERT INTO records(feed,kind,body,hash,status,created) VALUES(?,?,?,?,?,?)',(feed,'record',body,sha(body),'QUEUED',iso()))

def select(db,feed,n):
    return db.execute("SELECT id,body,hash FROM records WHERE feed=? AND status='QUEUED' ORDER BY id LIMIT ?",(feed,n)).fetchall()

def index_parse_envelope(data):
    try:
        if not isinstance(data,str) or not data.startswith(PREFIX):return None
        e=parse(data[len(PREFIX):])
        if not isinstance(e,dict) or type(e.get('v')) is not int or e['v']!=1 or e.get('m') not in ('hash','inline'):return None
        if not isinstance(e.get('f'),str) or not 1<=len(e['f'])<=128:return None
        if type(e.get('n')) is not int or not 1<=e['n']<=10000 or not ishash(e.get('h')):return None
        if e['m']=='inline' and (not isinstance(e.get('r'),list) or len(e['r'])!=e['n'] or sha(canonical(e['r']))!=e['h']):return None
        return e
    except (ValueError,TypeError,OverflowError):return None

def prepare(args,rows):
    body=[parse(r[1]) for r in rows]
    # Stored hashes are checked before fees can be spent.
    if any(sha(canonical(parse(r[1])))!=r[2] for r in rows):raise RuntimeError('Local queued record hash mismatch')
    e={'v':1,'f':args.feed,'n':len(rows),'h':sha(canonical(body)),'m':args.mode}
    if args.mode=='inline':e['r']=body
    payload=PREFIX+canonical(e)
    size=len(payload.encode('utf8'))
    if size>min(args.max_bytes,MAX_PAYLOAD):raise RuntimeError(f'Payload is {size} bytes, limit {min(args.max_bytes,MAX_PAYLOAD)}; use hash mode or a smaller batch')
    return payload,canonical(body)

def publish(args,db):
    if args.broadcast:
        if not args.owner or not args.max_fee_atoms or args.max_fee_atoms<1:raise RuntimeError('--broadcast requires --owner and positive --max-fee-atoms')
        cap=rpc(args,'getdatafeedinfo',{})
        if isinstance(cap,dict) and cap.get('wallet_publish_enabled') is not True:raise RuntimeError('Core wallet publication disabled; requires local RPC and TRU_RPC_WALLET_SEND_ENABLE=1 on Core')
        if not isinstance(cap,dict) or cap.get('format')!='TRU_DATAFEED_RPC_V1' or cap.get('fee_cap_enforced') is not True or cap.get('max_payload_bytes')!=254:
            raise RuntimeError('Matching fee-bounded DataFeed Core upgrade required')
    batch_id=None
    try:
        db.execute('BEGIN IMMEDIATE')
        # Never create another batch for this feed while one has an unknown outcome.
        if db.execute("SELECT 1 FROM records WHERE feed=? AND status='SUBMITTING' LIMIT 1",(args.feed,)).fetchone():
            raise RuntimeError('Unresolved SUBMITTING rows for this feed; reconcile them before publishing again')
        rows=select(db,args.feed,args.batch_size)
        if not rows:db.rollback();print('QUEUE_EMPTY=YES');return
        payload,body=prepare(args,rows)
        print(f'BATCH records={len(rows)} bytes={len(payload.encode())} sha256={sha(body)}')
        if not args.broadcast:db.rollback();print('DRY_RUN=YES; BROADCAST=NO');return
        c=db.execute('INSERT INTO batches(feed,owner,payload,body,status,created) VALUES(?,?,?,?,?,?)',(args.feed,args.owner,payload,body,'SUBMITTING',iso()));batch_id=c.lastrowid
        db.executemany('INSERT INTO batch_records VALUES(?,?)',[(batch_id,r[0]) for r in rows])
        db.executemany("UPDATE records SET status='SUBMITTING' WHERE id=?",[(r[0],) for r in rows]);db.commit()
    except Exception:db.rollback();raise
    print('BATCH_ID='+str(batch_id),flush=True)
    try:
        result=rpc(args,'publishdatafeed',{'data':payload,'owner':args.owner,'max_fee_atoms':args.max_fee_atoms})
        txid=result.get('txid') if isinstance(result,dict) else None
        if not ishash(txid):raise RuntimeError('Invalid publication response; outcome unknown')
    except Exception:
        print('SUBMISSION_UNCERTAIN=YES; journal retained; do not requeue or blindly rebroadcast',file=sys.stderr);raise
    with db:
        db.execute("UPDATE batches SET status='OBSERVED',txid=? WHERE id=?",(txid,batch_id))
        db.execute("UPDATE records SET status='OBSERVED',txid=? WHERE id IN (SELECT record_id FROM batch_records WHERE batch_id=?)",(txid,batch_id))
    print('TXID='+txid+'; STATUS=OBSERVED (not confirmed)')

def lookup(args,txid):
    if not ishash(txid):raise RuntimeError('Invalid txid')
    r=rpc(args,'getdatafeedrecord',{'txid':txid})
    if not isinstance(r,dict) or r.get('txid')!=txid or r.get('source')!='transaction_output_bytes':raise RuntimeError('Unexpected DataFeed record response')
    e=index_parse_envelope(r.get('data'))
    if e is None:raise RuntimeError('Invalid DataFeed envelope or inline hash')
    confirmed=r.get('chain_confirmed') is True and r.get('tx_state')=='ACTIVE' and type(r.get('confirmations')) is int and r['confirmations']>=1 and type(r.get('blockheight')) is int and r['blockheight']>=1 and ishash(r.get('blockhash'))
    return {'txid':txid,'feed':e['f'],'count':e['n'],'mode':e['m'],'hash':e['h'],'records':e.get('r'),
        'inline_hash_valid':True if e['m']=='inline' else None,'chain_confirmed':bool(confirmed),'confirmations':r.get('confirmations',0),
        'blockheight':r.get('blockheight'),'blockhash':r.get('blockhash'),'source':r['source'],'payload':r['data']}

def index_setup(path):
    db=private_db(path)
    db.execute('CREATE TABLE IF NOT EXISTS discovered(txid TEXT PRIMARY KEY,height INTEGER NOT NULL,blockhash TEXT NOT NULL,feed TEXT NOT NULL,mode TEXT NOT NULL,commitment TEXT NOT NULL,count INTEGER NOT NULL,records_json TEXT,confirmed INTEGER NOT NULL,indexed_at TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS scanned(height INTEGER PRIMARY KEY,blockhash TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS index_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
    version=db.execute("SELECT value FROM index_meta WHERE key='source'").fetchone()
    if version!=('transaction_output_bytes_v1',):
        # This is a rebuildable discovery cache, never the publication journal.
        had=db.execute('SELECT count(*) FROM scanned').fetchone()[0]
        db.execute('DELETE FROM discovered');db.execute('DELETE FROM scanned')
        db.execute("INSERT OR REPLACE INTO index_meta VALUES('source','transaction_output_bytes_v1')")
        if had:print('LEGACY_DISCOVERY_CACHE_RESET=YES; rescan desired ranges; publication journal unchanged',file=sys.stderr)
    db.commit();return db

def check_index_chain(args,db,tip):
    rows=db.execute('SELECT height,blockhash FROM scanned ORDER BY height DESC').fetchall()
    for h,bh in rows:
        if h<=tip:
            actual=rpc(args,'getblockbyheight',{'height':h})
            if actual.get('hash')==bh:return
        with db:
            db.execute('DELETE FROM discovered WHERE height>=?',(h,));db.execute('DELETE FROM scanned WHERE height>=?',(h,))
        print('PRUNED_STALE_INDEX_FROM_HEIGHT='+str(h),file=sys.stderr)

def index_scan(args,db):
    tip=rpc(args,'getblockcount',{})
    if type(tip) is not int or tip<1:raise RuntimeError('Invalid chain height')
    end=tip if args.to_height is None else min(tip,args.to_height)
    if args.from_height<1 or end<args.from_height or end-args.from_height+1>args.max_blocks:raise RuntimeError('Invalid range; TRU genesis is height 1; bound range with --max-blocks')
    check_index_chain(args,db,tip)
    found=0
    for h in range(args.from_height,end+1):
        # Always scan all feeds: a feed filter must not poison the shared height cache.
        b=rpc(args,'getdatafeedblock',{'height':h})
        if not isinstance(b,dict) or b.get('height')!=h or not ishash(b.get('hash')) or not isinstance(b.get('records'),list):raise RuntimeError('Invalid block response')
        prev=db.execute('SELECT blockhash FROM scanned WHERE height=?',(h,)).fetchone()
        if prev and prev[0]!=b['hash']:
            with db:db.execute('DELETE FROM discovered WHERE height>=?',(h,));db.execute('DELETE FROM scanned WHERE height>=?',(h,))
        if prev and prev[0]==b['hash'] and not args.rescan:continue
        batch=[]
        for candidate in b['records']:
            env=index_parse_envelope(candidate.get('data'))
            if env is None:continue
            r=lookup(args,candidate.get('txid'))
            if not r['chain_confirmed'] or r['blockheight']!=h or r['blockhash']!=b['hash'] or r['payload']!=candidate['data']:
                raise RuntimeError('Chain changed during scan; rerun scan')
            batch.append((r['txid'],h,b['hash'],r['feed'],r['mode'],r['hash'],r['count'],canonical(r['records']) if r['mode']=='inline' else None,1,iso()))
        endblock=rpc(args,'getblockbyheight',{'height':h})
        if endblock.get('hash')!=b['hash']:raise RuntimeError('Chain changed during scan; rerun scan')
        with db:
            db.execute('DELETE FROM discovered WHERE height=?',(h,))
            db.executemany('INSERT OR REPLACE INTO discovered VALUES(?,?,?,?,?,?,?,?,?,?)',batch)
            db.execute('INSERT OR REPLACE INTO scanned VALUES(?,?)',(h,b['hash']))
        found+=len(batch);print(f'SCANNED_HEIGHT={h} DISCOVERED={len(batch)}',flush=True)
    print(f'SCAN_COMPLETE=YES FOUND={found} TIP={tip} INDEX_SCOPE=ALL_FEEDS')

def write_output(text,path):
    if path:
        with pathlib.Path(path).expanduser().open('x',encoding='utf8') as f:f.write(text)
        print('EXPORTED_FILE='+path)
    else:print(text,end='')

def index_query(args,db):
    where=[];vals=[]
    if args.feed:where.append('feed=?');vals.append(args.feed)
    if args.txid:where.append('txid=?');vals.append(args.txid)
    sql='SELECT txid,height,blockhash,feed,mode,commitment,count,records_json FROM discovered'
    if where:sql+=' WHERE '+' AND '.join(where)
    sql+=' ORDER BY height,txid LIMIT ?';vals.append(args.limit)
    rows=[]
    for a in db.execute(sql,vals):
        r=dict(zip(('txid','height','blockhash','feed','mode','sha256','count'),a[:7]));r['records']=parse(a[7]) if a[7] else None;r['chain_status']='CACHED_NOT_RECHECKED'
        if args.live:
            live=lookup(args,a[0]);r['chain_status']='CONFIRMED' if live['chain_confirmed'] and live['blockhash']==a[2] and live['hash']==a[5] else 'UNVERIFIED_OR_REORGED'
        rows.append(r)
    if args.format=='json':text=json.dumps(rows,indent=2,ensure_ascii=False)+'\n'
    elif args.format=='jsonl':text=''.join(canonical(r)+'\n' for r in rows)
    else:
        buf=io.StringIO();fields=['txid','height','blockhash','feed','mode','sha256','count','records','chain_status'];w=csv.DictWriter(buf,fieldnames=fields);w.writeheader()
        for r in rows:w.writerow({**r,'records':canonical(r['records'])})
        text=buf.getvalue()
    write_output(text,args.output)

def reconcile(args,db):
    r=lookup(args,args.txid)
    if r['feed']!=args.feed:raise RuntimeError('Feed mismatch')
    if args.batch_id is None:
        print(json.dumps(r,indent=2));print('RECONCILE_READ_ONLY=YES; use --batch-id for new journal batches after review');return
    row=db.execute('SELECT payload,body,txid FROM batches WHERE id=? AND feed=?',(args.batch_id,args.feed)).fetchone()
    if not row:raise RuntimeError('Batch not found; legacy SUBMITTING rows require separate review')
    if r['payload']!=row[0] or sha(row[1])!=r['hash'] or not r['chain_confirmed']:raise RuntimeError('Exact confirmed batch match required')
    if row[2] and row[2]!=args.txid:raise RuntimeError('Batch already associated with a different txid')
    # This is a local association to a user-selected confirmed tx, not proof the
    # original timed-out RPC submitted it. It never submits or requeues anything.
    with db:
        db.execute("UPDATE batches SET status='CONFIRMED',txid=? WHERE id=?",(args.txid,args.batch_id))
        db.execute("UPDATE records SET status='CONFIRMED',txid=? WHERE id IN (SELECT record_id FROM batch_records WHERE batch_id=?)",(args.txid,args.batch_id))
    print('LOCAL_BATCH_ASSOCIATED=YES; CHAIN_CHECKED_NOW=YES; BROADCAST=NO')

def main():
    p=argparse.ArgumentParser(description='TRU DataFeed 0.08.1: explicit fee-bounded publication and read-only discovery')
    p.add_argument('--cli',default=os.path.expanduser('~/NEW_TRU/build-native/bin/tru-cli'))
    p.add_argument('--db',default='~/.local/share/tru/datafeed-v1.sqlite3')
    p.add_argument('--index-db',default='~/.local/share/tru/datafeed-v2-index.sqlite3')
    s=p.add_subparsers(dest='cmd',required=True)
    a=s.add_parser('queue');a.add_argument('--feed',required=True);g=a.add_mutually_exclusive_group();g.add_argument('--record');g.add_argument('--file');g.add_argument('--stdin',action='store_true')
    a=s.add_parser('publish');a.add_argument('--feed',required=True);a.add_argument('--owner');a.add_argument('--mode',choices=['hash','inline'],default='hash');a.add_argument('--batch-size',type=int,default=100);a.add_argument('--max-bytes',type=int,default=254);a.add_argument('--broadcast',action='store_true');a.add_argument('--max-fee-atoms',type=int)
    a=s.add_parser('get');a.add_argument('txid');a.add_argument('--output')
    a=s.add_parser('verify');a.add_argument('txid');a.add_argument('--file')
    a=s.add_parser('list');a.add_argument('--feed')
    a=s.add_parser('batches');a.add_argument('--feed')
    a=s.add_parser('export-batch');a.add_argument('batch_id',type=int);a.add_argument('--output',required=True)
    a=s.add_parser('reconcile');a.add_argument('--feed',required=True);a.add_argument('--txid',required=True);a.add_argument('--batch-id',type=int)
    a=s.add_parser('scan');a.add_argument('--from-height',type=int,required=True);a.add_argument('--to-height',type=int);a.add_argument('--max-blocks',type=int,default=100);a.add_argument('--feed',help='compatibility option; all feeds are indexed, filter with search');a.add_argument('--rescan',action='store_true')
    a=s.add_parser('search');a.add_argument('--feed');a.add_argument('--txid');a.add_argument('--limit',type=int,default=100);a.add_argument('--format',choices=['json','jsonl','csv'],default='json');a.add_argument('--output');a.add_argument('--live',action='store_true')
    a=s.add_parser('watch');a.add_argument('--feed',required=True);a.add_argument('--queue-db');a.add_argument('--interval',type=int,default=300);a.add_argument('--batch-size',type=int,default=100);a.add_argument('--once',action='store_true')
    args=p.parse_args()
    if getattr(args,'feed',None) and not re.fullmatch('[A-Za-z0-9._:-]{1,128}',args.feed):raise RuntimeError('Feed label must be 1..128 ASCII letters/digits or . _ : -')
    if hasattr(args,'batch_size') and not 1<=args.batch_size<=10000:raise RuntimeError('batch-size must be 1..10000')
    if args.cmd=='publish' and not 100<=args.max_bytes<=254:raise RuntimeError('max-bytes must be 100..254')
    if args.cmd=='scan' and not 1<=args.max_blocks<=5000:raise RuntimeError('max-blocks must be 1..5000')
    if args.cmd=='search' and not 1<=args.limit<=10000:raise RuntimeError('limit must be 1..10000')
    if args.cmd in ('scan','search'):
        db=index_setup(args.index_db)
        try:(index_scan if args.cmd=='scan' else index_query)(args,db)
        finally:db.close()
        return
    if args.cmd in ('get','verify'):
        r=lookup(args,args.txid)
        if args.cmd=='verify':
            if args.file:
                body=parse(pathlib.Path(args.file).expanduser().read_text())
                r['provided_data_hash_valid']=isinstance(body,list) and len(body)==r['count'] and sha(canonical(body))==r['hash']
            r['verified']=bool(r['chain_confirmed'] and (r['inline_hash_valid'] is True or r.get('provided_data_hash_valid') is True))
        write_output(json.dumps(r,indent=2,ensure_ascii=False)+'\n',getattr(args,'output',None))
        if args.cmd=='verify' and not r['verified']:raise RuntimeError('Verification incomplete or failed')
        return
    if args.cmd=='watch':
        if args.interval<5:raise RuntimeError('interval must be at least 5 seconds')
        path=pathlib.Path(args.queue_db or args.db).expanduser().absolute()
        if not path.is_file() or path.is_symlink():raise RuntimeError('Existing regular queue DB required')
        while True:
            db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
            try:rows=select(db,args.feed,args.batch_size)
            finally:db.close()
            print(f'DRY_RUN=YES AUTO_BROADCAST=DISABLED COUNT={len(rows)} HASH='+sha(canonical([parse(r[1]) for r in rows])),flush=True)
            if args.once:return
            time.sleep(args.interval)
    db=dbopen(args.db)
    try:
        if args.cmd=='queue':
            n=0
            with db:
                for rec in input_records(args):store(db,args.feed,rec);n+=1
            print('QUEUED='+str(n))
        elif args.cmd=='publish':publish(args,db)
        elif args.cmd=='reconcile':reconcile(args,db)
        elif args.cmd=='export-batch':
            row=db.execute('SELECT body FROM batches WHERE id=?',(args.batch_id,)).fetchone()
            if not row:raise RuntimeError('Batch not found')
            write_output(row[0]+'\n',args.output)
        elif args.cmd in ('list','batches'):
            fields=['id','feed','hash','txid','status','created'] if args.cmd=='list' else ['id','feed','owner','txid','status','created']
            table='records' if args.cmd=='list' else 'batches';q='SELECT '+','.join(fields)+' FROM '+table
            vals=[]
            if args.feed:q+=' WHERE feed=?';vals=[args.feed]
            rows=db.execute(q+' ORDER BY id DESC LIMIT 1000',vals).fetchall();print(json.dumps([dict(zip(fields,r)) for r in rows],indent=2))
    finally:db.close()

if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,TypeError,OSError,sqlite3.Error,subprocess.TimeoutExpired) as e:print('STOP:',e,file=sys.stderr);sys.exit(2)
    except KeyboardInterrupt:print('STOP: interrupted; retain journal and inspect any SUBMITTING batch',file=sys.stderr);sys.exit(130)

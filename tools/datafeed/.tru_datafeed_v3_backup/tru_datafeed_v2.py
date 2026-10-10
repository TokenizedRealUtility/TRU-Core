#!/usr/bin/env python3
"""TRU DataFeed v2 read-only chain scanner, retrieval/export and safe queue watcher.
No signing or broadcasting functionality exists in this tool.
"""
import argparse, csv, json, os, pathlib, sqlite3, subprocess, sys, time, hashlib
from datetime import datetime, timezone

PREFIX='TRUDF1:'
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def utc():return datetime.now(timezone.utc).isoformat()
def sha(x):return hashlib.sha256(x.encode('utf-8')).hexdigest()
def rpc(cli,method,params):
    p=subprocess.run([cli,'-json','raw',method,canon(params)],capture_output=True,text=True,timeout=60)
    if p.returncode:raise RuntimeError('RPC failed '+method+': '+p.stderr[:300])
    try:r=json.loads(p.stdout)
    except ValueError:raise RuntimeError('Malformed RPC response for '+method)
    if isinstance(r,dict) and r.get('error'):raise RuntimeError('RPC error '+method+': '+str(r['error'])[:200])
    if isinstance(r,dict) and r.get('jsonrpc')=='2.0':return r.get('result')
    return r

def setup(dbpath):
    path=pathlib.Path(dbpath).expanduser(); path.parent.mkdir(parents=True,exist_ok=True)
    if not path.is_file():
        fd=os.open(str(path),os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
    if path.is_symlink():raise RuntimeError('Symlink DB refused')
    db=sqlite3.connect(str(path),timeout=20)
    db.execute('PRAGMA busy_timeout=20000')
    db.execute('CREATE TABLE IF NOT EXISTS discovered(txid TEXT PRIMARY KEY, height INTEGER NOT NULL, blockhash TEXT NOT NULL, feed TEXT NOT NULL, mode TEXT NOT NULL, commitment TEXT NOT NULL, count INTEGER NOT NULL, records_json TEXT, confirmed INTEGER NOT NULL, indexed_at TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS scanned(height INTEGER PRIMARY KEY, blockhash TEXT NOT NULL)')
    db.commit();return db

def parse_envelope(data):
    if not isinstance(data,str) or not data.startswith(PREFIX):return None
    obj=json.loads(data[len(PREFIX):])
    if not isinstance(obj,dict) or obj.get('v')!=1 or obj.get('m') not in ('hash','inline'):return None
    if not isinstance(obj.get('f'),str) or not (1<=len(obj['f'])<=128):return None
    if not isinstance(obj.get('n'),int) or isinstance(obj['n'],bool) or not 1<=obj['n']<=10000:return None
    h=obj.get('h')
    if not isinstance(h,str) or len(h)!=64 or any(c not in '0123456789abcdef' for c in h):return None
    if obj['m']=='inline':
        if not isinstance(obj.get('r'),list) or len(obj['r'])!=obj['n'] or sha(canon(obj['r']))!=h:return None
    return obj

def scan(args,db):
    tip=rpc(args.cli,'getblockcount',{})
    if not isinstance(tip,int) or isinstance(tip,bool) or tip<0:raise RuntimeError('invalid chain height')
    end=tip if args.to_height is None else min(tip,args.to_height)
    start=args.from_height
    if start<0 or end<start or end-start+1>args.max_blocks:raise RuntimeError('invalid scan range or above --max-blocks limit')
    found=0;probed=0
    for height in range(start,end+1):
        block=rpc(args.cli,'getblockbyheight',{'height':height})
        if not isinstance(block,dict) or not isinstance(block.get('hash'),str) or not isinstance(block.get('tx'),list):raise RuntimeError('invalid block RPC response')
        bh=block['hash']; prev=db.execute('SELECT blockhash FROM scanned WHERE height=?',(height,)).fetchone()
        if prev and prev[0]!=bh:
            # Roll back affected scan height and all later indexed data, then stop.
            with db:
                db.execute('DELETE FROM discovered WHERE height>=?',(height,))
                db.execute('DELETE FROM scanned WHERE height>=?',(height,))
            raise RuntimeError('REORG_DETECTED at height '+str(height)+'; orphaned local index entries pruned, rescan range')
        if prev and not args.rescan:continue
        if len(block['tx'])>args.max_tx_per_block:raise RuntimeError('block exceeds scanner max-tx-per-block; stop')
        batch=[]
        for txid in block['tx']:
            if not isinstance(txid,str) or len(txid)!=64:raise RuntimeError('bad txid in block')
            probed+=1
            try:details=rpc(args.cli,'getTRUScriptDetails',{'txid':txid})
            except RuntimeError as e:
                if 'TRUScript not found' in str(e) or 'Not a TRUScript' in str(e):continue
                raise
            if not isinstance(details,dict):raise RuntimeError('malformed TRUScript details')
            env=parse_envelope(details.get('data'))
            if not env:continue
            if args.feed and env['f']!=args.feed:continue
            # Require explicit live, active confirmation from Core.
            status=rpc(args.cli,'gettransaction',{'txid':txid})
            confirmed=isinstance(status,dict) and status.get('txState')=='CONFIRMED' and status.get('active') is True and status.get('confirmations',0)>=1
            if not confirmed:continue
            batch.append((txid,height,bh,env['f'],env['m'],env['h'],env['n'],canon(env.get('r')) if env['m']=='inline' else None,1,utc()))
        with db:
            if args.rescan:db.execute('DELETE FROM discovered WHERE height=?',(height,))
            db.executemany('INSERT OR REPLACE INTO discovered VALUES(?,?,?,?,?,?,?,?,?,?)',batch)
            db.execute('INSERT OR REPLACE INTO scanned VALUES(?,?)',(height,bh))
        found+=len(batch)
        print('SCANNED_HEIGHT='+str(height)+' DISCOVERED='+str(len(batch)),flush=True)
    print('SCAN_COMPLETE=YES FOUND='+str(found)+' TX_PROBES='+str(probed)+' TIP='+str(tip))

def query(args,db):
    where=[]; vals=[]
    if args.feed:where.append('feed=?');vals.append(args.feed)
    if args.txid:where.append('txid=?');vals.append(args.txid)
    sql='SELECT txid,height,blockhash,feed,mode,commitment,count,records_json FROM discovered'
    if where:sql+=' WHERE '+' AND '.join(where)
    sql+=' ORDER BY height,txid LIMIT ?';vals.append(args.limit)
    records=[]
    for a in db.execute(sql,vals):
        records.append({'txid':a[0],'height':a[1],'blockhash':a[2],'feed':a[3],'mode':a[4],'sha256':a[5],'count':a[6],'records':json.loads(a[7]) if a[7] else None})
    if args.format=='json':out=json.dumps(records,indent=2,ensure_ascii=False)+'\n'
    elif args.format=='jsonl':out=''.join(canon(r)+'\n' for r in records)
    else:
        import io
        buf=io.StringIO();writer=csv.DictWriter(buf,fieldnames=['txid','height','blockhash','feed','mode','sha256','count','records_json']);writer.writeheader()
        for r in records:writer.writerow({**{k:r[k] for k in ('txid','height','blockhash','feed','mode','count')},'sha256':r['sha256'],'records_json':canon(r['records']) if r['records'] is not None else ''})
        out=buf.getvalue()
    if args.output:
        p=pathlib.Path(args.output).expanduser()
        if p.exists():raise RuntimeError('Output exists; refusing overwrite')
        with p.open('x',encoding='utf-8') as f:f.write(out)
        print('EXPORTED='+str(len(records))+' FILE='+str(p))
    else:sys.stdout.write(out)

def watch(args):
    if args.interval<5 or args.batch_size<1 or args.batch_size>10000:raise RuntimeError('invalid limits')
    # Deliberately read-only: checks v1 local queue, previews hash only. No fees.
    path=pathlib.Path(args.queue_db).expanduser()
    if not path.is_file():raise RuntimeError('v1 queue database missing')
    while True:
        db=sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,timeout=10)
        try:
            rows=db.execute("SELECT id,body FROM records WHERE feed=? AND status='QUEUED' ORDER BY id LIMIT ?",(args.feed,args.batch_size)).fetchall()
        finally:db.close()
        if rows:
            payload=canon([json.loads(r[1]) for r in rows]);print('DRY_RUN=YES FEED='+args.feed+' COUNT='+str(len(rows))+' HASH='+sha(payload)+' AUTO_BROADCAST=DISABLED',flush=True)
        else:print('QUEUE_EMPTY='+args.feed,flush=True)
        if args.once:break
        time.sleep(args.interval)

def main():
    p=argparse.ArgumentParser(description='TRU DataFeed 02: bounded chain discovery + safe automated preview')
    p.add_argument('--cli',default=os.path.expanduser('~/NEW_TRU/build-native/bin/tru-cli'))
    p.add_argument('--index-db',default='~/.local/share/tru/datafeed-v2-index.sqlite3')
    s=p.add_subparsers(dest='command',required=True)
    a=s.add_parser('scan');a.add_argument('--from-height',type=int,required=True);a.add_argument('--to-height',type=int);a.add_argument('--max-blocks',type=int,default=100);a.add_argument('--max-tx-per-block',type=int,default=20000);a.add_argument('--feed');a.add_argument('--rescan',action='store_true')
    a=s.add_parser('search');a.add_argument('--feed');a.add_argument('--txid');a.add_argument('--limit',type=int,default=100);a.add_argument('--format',choices=['json','jsonl','csv'],default='json');a.add_argument('--output')
    a=s.add_parser('watch');a.add_argument('--feed',required=True);a.add_argument('--queue-db',default='~/.local/share/tru/datafeed-v1.sqlite3');a.add_argument('--interval',type=int,default=300);a.add_argument('--batch-size',type=int,default=100);a.add_argument('--once',action='store_true')
    args=p.parse_args()
    if args.command=='watch':watch(args);return
    if args.command=='search' and not 1<=args.limit<=10000:raise RuntimeError('invalid limit')
    if args.command=='scan' and (args.max_blocks<1 or args.max_blocks>5000 or args.max_tx_per_block<1 or args.max_tx_per_block>200000):raise RuntimeError('invalid scan bounds')
    db=setup(args.index_db)
    if args.command=='scan':scan(args,db)
    else:query(args,db)

if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError,OSError,sqlite3.Error,json.JSONDecodeError) as e:print('STOP:',e,file=sys.stderr);sys.exit(2)

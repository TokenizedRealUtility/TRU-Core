"""Agent-owned Market handshake process. No funding, signing or broadcast entry point."""
import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = 'TRU-MARKET-PROCESS-01D'
FIELDS = ('schemaVersion','pairId','side','baseAtoms','quoteAtoms','baseMinConfirmations',
          'quoteMinConfirmations','fundingOrder','makerRefundSeconds','takerRefundSeconds','lifeSeconds')
TERMINAL = {'BOUND','EXPIRED','RELEASED','WITHDRAWN'}
MESSAGES = {
 'POSTING':'Posting advert', 'ACTIVE':'Advert posted — waiting for a taker',
 'RESERVING':'Reserving advert', 'HELD':'Reservation secured',
 'OFFER_CREATED':'Fresh offer ready — waiting for taker acceptance',
 'WAITING_MAKER':'Reservation secured — waiting for maker',
 'ACCEPTANCE_CREATED':'Acceptance sent — waiting for maker finalization',
 'FINALIZATION_STARTED':'Agreement verified — preparing canonical swap record',
 'FINALIZED_MAKER':'Maker swap ready — waiting for taker verification',
 'FINALIZED_TAKER':'Both agreements verified — confirming binding',
 'BOUND':'Swap ready — funding is handled on the swap page',
 'EXPIRED':'Reservation or advert expired', 'RELEASED':'Reservation released',
 'WITHDRAWN':'Advert withdrawn', 'WITHDRAWING':'Withdrawing advert',
}
class ProcessCheck(ValueError): pass
def check(ok, message='Market response identity mismatch'):
    if not ok: raise ProcessCheck(message)
def hx(value, n=32):
    check(isinstance(value,str) and re.fullmatch('[0-9a-f]{'+str(n)+'}',value), 'Invalid process identifier')
    return value
def canonical(obj): return json.dumps(obj,sort_keys=True,separators=(',',':'))
def intent(obj):
    check(isinstance(obj,dict) and all(k in obj for k in FIELDS), 'Incomplete advert terms')
    clean={k:obj[k] for k in FIELDS}
    check(clean['schemaVersion']=='TRU-MARKET-INTENT-V1' and clean['pairId']=='TRU_BSTY', 'Unsupported market pair')
    check(clean['side'] in ('SELL_BASE','BUY_BASE') and clean['fundingOrder']=='MAKER_FIRST', 'Unsupported role order')
    for k in ('baseAtoms','quoteAtoms'):
        check(isinstance(clean[k],str) and re.fullmatch('[1-9][0-9]{0,19}',clean[k]) and int(clean[k])<=2**64-1, 'Invalid atom amount')
    for k in ('baseMinConfirmations','quoteMinConfirmations','makerRefundSeconds','takerRefundSeconds','lifeSeconds'):
        check(type(clean[k]) is int and 0<clean[k]<=31536000,'Invalid advert parameter')
    check(clean['baseMinConfirmations']==clean['quoteMinConfirmations']<=10000,'Confirmation split is unsupported')
    check(clean['makerRefundSeconds']-clean['takerRefundSeconds']>=21600,'Unsafe refund gap')
    check(300<=clean['lifeSeconds']<=604800,'Advert lifetime must be 5 minutes to 7 days')
    check(clean['makerRefundSeconds']%3600==clean['takerRefundSeconds']%3600==0,'Refund windows must be whole hours')
    return clean
def terms(i):
    sell=i['side']=='SELL_BASE'
    def coin(a): return str(int(a)//100000000)+'.'+str(int(a)%100000000).zfill(8)
    return dict(giveChain='tru' if sell else 'bsty',getChain='bsty' if sell else 'tru',
        giveAmount=coin(i['baseAtoms'] if sell else i['quoteAtoms']),
        getAmount=coin(i['quoteAtoms'] if sell else i['baseAtoms']),
        ownHours=i['makerRefundSeconds']//3600,theirHours=i['takerRefundSeconds']//3600,
        minConf=i['baseMinConfirmations'])

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None
class MarketHTTPError(Exception):
    def __init__(self,status): self.status=status
class Client:
    def __init__(self):
        self.origin=os.environ.get('TRU_SWAP_MARKET_ORIGIN','https://market-api.tokenizedrealutility.com').rstrip('/')
        check(self.origin in ('https://market-api.tokenizedrealutility.com','http://127.0.0.1:8650'), 'Market origin must be the public Market or local port 8650')
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def call(self,path,body=None):
        check(path.startswith('/v1/market/') and '..' not in path)
        req=urllib.request.Request(self.origin+path,data=None if body is None else canonical(body).encode(),
            headers={'Content-Type':'application/json','Accept':'application/json','User-Agent':VERSION})
        try:
            with self.opener.open(req,timeout=10) as response:
                data=response.read(262145)
                check(len(data)<=262144,'Market response exceeds limit')
                obj=json.loads(data)
        except urllib.error.HTTPError as e:
            e.close();raise MarketHTTPError(e.code) from None
        check(isinstance(obj,dict) and obj.get('ok') is True,'Market response invalid')
        return obj

class MarketProcess:
    def __init__(self,agent,client=None):
        self.agent=agent;self.client=client or Client();self.lock=threading.RLock()
        self.halt=threading.Event();self.thread=None;self.file=None
        with agent.store.connect() as c:
            c.executescript('''CREATE TABLE IF NOT EXISTS market_processes(
                id TEXT PRIMARY KEY, data TEXT NOT NULL, due REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS market_offer_keys(process_key TEXT PRIMARY KEY,offer_id TEXT UNIQUE NOT NULL);''')
    def load(self,pid):
        with self.agent.store.connect() as c:
            row=c.execute('SELECT data FROM market_processes WHERE id=?',(pid,)).fetchone()
        check(row is not None,'Process not found');return json.loads(row['data'])
    def save(self,j,delay=0):
        j['updatedAt']=int(time.time())
        with self.agent.store.connect() as c:
            c.execute('INSERT INTO market_processes VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,due=excluded.due',
                      (j['id'],canonical(j),time.time()+delay))
    def public(self,j):
        return {k:v for k,v in dict(processId=j['id'],role=j['role'],advertId=j.get('advertId'),
            reservationId=j.get('reservationId'),state=j['state'],message=MESSAGES.get(j['state'],j['state']),
            error=j.get('error'),errorDetail=j.get('errorDetail'),swapId=j.get('swapId'),updatedAt=j.get('updatedAt'),
            advert=j.get('advert'),fundingStartedByProcess=False).items() if v is not None}
    def rows(self):
        with self.agent.store.connect() as c:
            return [json.loads(r['data']) for r in c.execute('SELECT data FROM market_processes ORDER BY due,id')]
    def route(self,action,body):
        if action=='list':return {'ok':True,'version':VERSION,'processes':[self.public(j) for j in self.rows()]}
        if action=='status':return {'ok':True,'process':self.public(self.load(hx(body.get('processId'))))}
        with self.lock:
            if action=='list':return {'ok':True,'version':VERSION,'processes':[self.public(j) for j in self.rows()]}
            if action=='status':return {'ok':True,'process':self.public(self.load(hx(body.get('processId'))))}
            if action=='retry':
                j=self.load(hx(body.get('processId')));j.pop('error',None);j.pop('errorDetail',None);j['failures']=0;self.save(j)
                return {'ok':True,'process':self.public(j)}
            if action=='withdraw':
                aid=hx(body.get('advertId'));matches=[j for j in self.rows() if j['role']=='maker' and j.get('advertId')==aid]
                check(len(matches)==1,'Advert is not owned by this Agent')
                j=matches[0];check(j['state'] not in TERMINAL,'Process is already closed')
                j['withdraw']=True;self.save(j);return {'ok':True,'process':self.public(j)}
            if action=='import-owner':
                # Explicit migration of a retained browser capability. No public-ID recovery.
                aid=hx(body.get('advertId'));cap=body.get('ownerToken')
                check(isinstance(cap,str) and re.fullmatch('[A-Za-z0-9_-]{32,128}',cap),'Invalid owner capability')
                for j in self.rows():
                    if j['role']=='maker' and j.get('advertId')==aid:
                        check(secrets.compare_digest(j['cap'],cap),'Owner capability mismatch')
                        return {'ok':True,'process':self.public(j)}
                view=self.client.call('/v1/market/adverts/'+aid+'/reservation',{'ownerToken':cap})
                advert=self.client.call('/v1/market/adverts/'+aid)['advert'];i=intent(advert)
                j=dict(id=secrets.token_hex(16),role='maker',state='ACTIVE',cap=cap,advertId=aid,advert=advert,intent=i)
                r=view.get('reservation')
                if r:
                    self.handoff(j,view);j['reservationId']=r['reservationId']
                if r and r.get('makerOffer'):
                    self.offer_terms(r['makerOffer'],i)
                    raw=r['makerOffer'].split(':',1)[1]
                    offer=json.loads(base64.b64decode(raw,validate=True))
                    session=self.agent.store.get_offer_session(offer['offerId'],'maker')
                    check(session and session['offer']==offer,'Original maker Agent session is required; capability retained')
                    check(not r.get('finalizationStartedAt') or session.get('final'), 'Old finalization outcome needs reconciliation; capability retained')
                    j['offer']=r['makerOffer'];j['state']='OFFER_CREATED'
                    if r['status']=='BOUND':
                        check(session.get('swapId') and session['swapId']==r['swapId']==r['makerSwapId']==r['takerSwapId'],'Imported swap identity differs')
                        j['swapId']=session['swapId'];j['state']='BOUND'
                    # Existing durable final is replayed by Agent import on the next cycle.
                check(len(self.rows())<2000,'Process capacity reached');self.save(j)
                return {'ok':True,'process':self.public(j)}
            if action=='import-take':
                rid=hx(body.get('reservationId'));cap=body.get('reservationToken')
                check(isinstance(cap,str) and re.fullmatch('[A-Za-z0-9_-]{32,128}',cap),'Invalid reservation capability')
                for existing in self.rows():
                    if existing.get('reservationId')==rid and existing['role']=='taker':
                        check(secrets.compare_digest(existing['cap'],cap),'Reservation capability mismatch')
                        return {'ok':True,'process':self.public(existing)}
                v=self.client.call('/v1/market/reservations/'+rid+'/status',{'reservationToken':cap})
                r=v['reservation'];aid=hx(r['advertId']);a=self.client.call('/v1/market/adverts/'+aid)['advert'];i=intent(a)
                check(r['status']=='HELD','Only an open reservation can be imported')
                check(not any(x['role']=='maker' and x.get('advertId')==aid for x in self.rows()),'Cannot import your own advert as taker')
                j=dict(id=secrets.token_hex(16),role='taker',state='HELD',cap=cap,advertId=aid,reservationId=rid,intent=i)
                self.handoff(j,v)
                if r.get('takerAcceptance'):
                    raw=r['takerAcceptance'].split(':',1)[1];accept=json.loads(base64.b64decode(raw,validate=True))
                    session=self.agent.store.get_offer_session(accept['offerId'],'taker')
                    check(session and session['acceptance']==accept,'Original taker Agent session required; capability retained')
                    j['acceptance']=r['takerAcceptance']
                check(len(self.rows())<2000,'Process capacity reached');self.save(j)
                return {'ok':True,'process':self.public(j)}
            check(action in ('post','take'),'Unknown process action')
            pid=hx(body.get('requestId'));i=intent(body.get('intent'));aid=hx(body.get('advertId')) if action=='take' else None
            fingerprint=canonical([action,i,aid])
            for j in self.rows():
                if j['id']==pid:
                    check(j.get('request')==fingerprint,'Request ID reused with different terms')
                    return {'ok':True,'process':self.public(j)}
                check(not (action=='take' and j['role']=='maker' and j.get('advertId')==aid),'Cannot take an advert owned by this Agent; use the other participant’s Agent')
                check(not (action=='take' and j['role']=='taker' and j.get('advertId')==aid and j['state'] not in TERMINAL),'An existing take is in My activity')
            check(len(self.rows())<2000,'Process capacity reached')
            j=dict(id=pid,role='maker' if action=='post' else 'taker',state='POSTING' if action=='post' else 'RESERVING',
                   cap=secrets.token_hex(32),intent=i,request=fingerprint)
            if aid:j['advertId']=aid
            self.save(j) # Capability and immutable intent BEFORE any public request.
            return {'ok':True,'process':self.public(j)}
    def offer_terms(self,blob,i):
        check(isinstance(blob,str) and blob.startswith('TRUSWAP2:'),'Invalid maker offer')
        data=blob.split(':',1)[1];obj=json.loads(base64.urlsafe_b64decode(data+'='*((-len(data))%4)))
        offer=self.agent.handshake.validate_offer(obj) # timing remains enforced by Agent import
        check(offer['terms']==self.agent._terms_from_browser(terms(i)),'Maker offer differs from approved advert')
    def handoff(self,j,v):
        r=v['reservation'];h=v['handoff'];i=j['intent'];t=terms(i)
        check(r['advertId']==j['advertId'] and h['advertId']==j['advertId'] and h['reservationId']==r['reservationId'])
        check(h.get('freshSwapRequired') is True and h.get('preexistingSwapIdAllowed') is False)
        check(h['makerGiveChain']==t['giveChain'] and h['makerGetChain']==t['getChain'])
        check(h['makerGiveAtoms']==(i['baseAtoms'] if i['side']=='SELL_BASE' else i['quoteAtoms']))
        check(h['makerGetAtoms']==(i['quoteAtoms'] if i['side']=='SELL_BASE' else i['baseAtoms']))
        for k in ('pairId','side','fundingOrder','baseMinConfirmations','quoteMinConfirmations','makerRefundSeconds','takerRefundSeconds'):
            check(h[k]==i[k])
        hx(r['reservationId']);return r
    def step(self,j):
        call=self.client.call
        if j['state'] in TERMINAL:return
        if j['state']=='POSTING':
            check(call('/v1/market/health').get('durableCapabilities') is True,'Upgrade Market API before posting')
            v=call('/v1/market/adverts',dict(j['intent'],durableOwnerToken=j['cap']))
            a=v['advert'];hx(a['advertId']);check(intent(a)==j['intent']);check(v['ownerToken']==j['cap'])
            j.update(advertId=a['advertId'],advert=a,state='ACTIVE');self.save(j);return
        aid=j['advertId'];ap='/v1/market/adverts/'+aid
        if j.get('withdraw'):
            v=call(ap+'/withdraw',{'ownerToken':j['cap']});check(v['advert']['status']=='WITHDRAWN')
            j['state']='WITHDRAWN';return
        if j['state']=='RESERVING':
            check(call('/v1/market/health').get('durableCapabilities') is True,'Upgrade Market API before taking')
            a=call(ap)['advert'];check(intent(a)==j['intent'],'Advert changed since approval')
            v=call('/v1/market/take',dict(advertId=aid,holdSeconds=300,durableReservationToken=j['cap']))
            r=self.handoff(j,v);check(v['reservationToken']==j['cap'])
            j.update(reservationId=r['reservationId'],state='HELD');self.save(j);return
        if j['role']=='maker':
            v=call(ap+'/reservation',{'ownerToken':j['cap']})
            if not v.get('reservation'):
                a=call(ap)['advert'];check(intent(a)==j['intent'])
                j['state']=a['status'];j['advert']=a;return
        else:
            v=call('/v1/market/reservations/'+hx(j['reservationId'])+'/status',{'reservationToken':j['cap']})
        r=self.handoff(j,v);rid=r['reservationId']
        if j.get('reservationId') and j['reservationId']!=rid:
            check(j['role']=='maker' and not j.get('swapId'),'Unexpected reservation identity')
            for k in ('offer','acceptance','final','swapId'):j.pop(k,None)
        j['reservationId']=rid
        if r['status']=='BOUND':
            check(j.get('swapId') and r['swapId']==r['makerSwapId']==r['takerSwapId']==j['swapId'],'Canonical swap identity differs')
            j['state']='BOUND';return
        if r['status']!='HELD':j['state']=r['status'];return
        rp='/v1/market/reservations/'+rid
        if j['role']=='maker':
            auth=dict(ownerToken=j['cap'],reservationId=rid)
            if not r.get('makerOffer'):
                with self.agent.lock:
                    made=self.agent.create_offer_v2(terms(j['intent']),process_key=j['id']+':'+rid)
                check(made['stage']=='OFFER_CREATED' and made['recordCreated'] is False)
                j['offer']=made['shareBlob'];self.save(j)
                call(ap+'/reservation/offer',dict(auth,offer=j['offer']));j['state']='OFFER_CREATED';return
            check(j.get('offer')==r['makerOffer'],'Maker offer does not match durable Agent session')
            if not r.get('takerAcceptance'):j['state']='OFFER_CREATED';return
            if not r.get('finalizationStartedAt'):
                call(ap+'/reservation/finalize-start',auth)
                j['state']='FINALIZATION_STARTED';return # observe committed barrier next cycle
            if not j.get('final'):
                with self.agent.lock: final=self.agent.import_offer_v2(r['takerAcceptance'])
                check(final['stage']=='FINALIZED_MAKER');j['swapId']=hx(final['record']['swapId'],64)
                j['final']=final['shareBlob'];self.save(j)
            call(ap+'/reservation/final',dict(auth,final=j['final'],swapId=j['swapId']))
            j['state']='FINALIZED_MAKER'
        else:
            if not r.get('makerOffer'):j['state']='WAITING_MAKER';return
            self.offer_terms(r['makerOffer'],j['intent'])
            if not j.get('acceptance'):
                with self.agent.lock: accepted=self.agent.import_offer_v2(r['makerOffer'])
                check(accepted['stage']=='ACCEPTANCE_CREATED' and accepted['recordCreated'] is False)
                j['acceptance']=accepted['shareBlob'];self.save(j)
            if not r.get('takerAcceptance'):
                call(rp+'/accept',dict(reservationToken=j['cap'],acceptance=j['acceptance']))
                j['state']='ACCEPTANCE_CREATED';return
            check(r['takerAcceptance']==j['acceptance'])
            if not r.get('makerFinal'):j['state']='ACCEPTANCE_CREATED';return
            check(r.get('finalizationStartedAt'),'Finalization barrier missing')
            if not j.get('swapId'):
                with self.agent.lock: final=self.agent.import_offer_v2(r['makerFinal'])
                check(final['stage']=='FINALIZED_TAKER');j['swapId']=hx(final['record']['swapId'],64);self.save(j)
            check(j['swapId']==r['makerSwapId'],'Canonical maker/taker swap IDs differ')
            result=call(rp+'/taker-bind',dict(reservationToken=j['cap'],swapId=j['swapId']))
            bound=result['reservation'];check(bound['status']=='BOUND' and bound['swapId']==j['swapId'])
            j['state']='BOUND'
    def cycle(self):
        with self.lock:
            with self.agent.store.connect() as c:
                rows=c.execute('SELECT id FROM market_processes WHERE due<=? ORDER BY due,id LIMIT 1',(time.time(),)).fetchall()
            for row in rows:
                if self.halt.is_set():break
                j=self.load(row['id'])
                if j['state'] in TERMINAL:self.save(j,86400);continue
                try:
                    self.step(j);j.pop('error',None);j.pop('errorDetail',None);j['failures']=0;delay=4
                except Exception as e:
                    # Never persist RPC stderr, response bodies, URLs or capabilities.
                    if isinstance(e,MarketHTTPError):code='MARKET_HTTP_'+str(e.status)
                    elif isinstance(e,ValueError):code='MARKET_IDENTITY_OR_TERMS_CHECK_FAILED'
                    else:
                        raw=getattr(e,'code','')
                        code=raw if raw in {'TRU_FRESH_ALLOCATOR_FAILED','BSTY_FRESH_KEY_FAILED','BSTY_FRESH_KEY_NOT_OWNED','SWAP_RECORD_CREATE_FAILED','BAD_OFFER_V2','BAD_ACCEPTANCE_V2','FINALIZE_FAILED'} else 'MARKET_OR_AGENT_UNAVAILABLE'
                    j['error']=code
                    j['errorDetail']=str(e) if isinstance(e,ProcessCheck) else 'Reconnect the affected service, then resume this saved process.'
                    j['failures']=min(10,j.get('failures',0)+1);delay=min(60,2**j['failures'])
                self.save(j,delay)
    def start(self):
        path=Path(str(self.agent.store.path)+'.market-process.lock')
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);self.file=os.fdopen(fd,'a')
        try:fcntl.flock(self.file,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except Exception:self.file.close();self.file=None;raise RuntimeError('Another Market worker owns this Agent database') from None
        def loop():
            while not self.halt.is_set():
                try:self.cycle()
                except Exception:pass # no sensitive diagnostic output; next cycle retries storage availability
                self.halt.wait(1)
        self.thread=threading.Thread(target=loop,name='tru-market-process',daemon=False);self.thread.start()
    def stop(self):
        self.halt.set()
        if self.thread:self.thread.join()
        if self.file:self.file.close();self.file=None

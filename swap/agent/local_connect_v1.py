"""Origin-bound local website approval; no wallet keys or RPC tokens returned."""
import hashlib,hmac,html,json,re,secrets,time
from urllib.parse import urlsplit,parse_qs
VERSION='TRU-LOCAL-CONNECT-01'
class ConnectError(ValueError):pass
def need(value,msg):
 if not value:raise ConnectError(msg)
def hashed(s):return hashlib.sha256(s.encode()).hexdigest()
class LocalConnect:
 def __init__(self,agent):
  self.agent=agent
  with agent.store.connect() as c:
   c.executescript('''CREATE TABLE IF NOT EXISTS local_connect_meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS local_connect_requests(id TEXT PRIMARY KEY,origin TEXT NOT NULL,proof_hash TEXT NOT NULL,csrf_hash TEXT,expires INTEGER NOT NULL,state TEXT NOT NULL,session_hash TEXT);
    ''')
   c.execute("INSERT OR IGNORE INTO local_connect_meta VALUES('seed',?)",(secrets.token_hex(32),))
 def local(self,handler):
  expected='127.0.0.1:'+str(handler.server.server_port)
  need(handler.headers.get('Host')==expected,'Local approval is available on this computer only')
  need(handler.client_address[0]=='127.0.0.1','Loopback connection required')
  need(not any(k.lower().startswith(('x-forwarded-','cf-')) or k.lower()=='forwarded' for k in handler.headers),'Proxied local approval is forbidden')
  return 'http://'+expected
 def request(self,origin,proof):
  need(origin in self.agent.origins and origin.startswith('https://'),'Website origin not allowed')
  need(isinstance(proof,str) and re.fullmatch('[0-9a-f]{64}',proof),'Invalid browser challenge')
  now=int(time.time());rid=secrets.token_hex(16)
  with self.agent.store.connect() as c:
   c.execute('BEGIN IMMEDIATE');c.execute('DELETE FROM local_connect_requests WHERE expires<?',(now,))
   need(c.execute('SELECT COUNT(*) FROM local_connect_requests').fetchone()[0]<32,'Too many pending connections; wait five minutes')
   c.execute('INSERT INTO local_connect_requests VALUES(?,?,?,NULL,?,?,NULL)',(rid,origin,proof,now+300,'PENDING'));c.execute('COMMIT')
  return {'ok':True,'requestId':rid,'expiresAt':now+300}
 def page(self,rid):
  need(isinstance(rid,str) and re.fullmatch('[0-9a-f]{32}',rid),'Invalid connection request')
  csrf=secrets.token_hex(32)
  with self.agent.store.connect() as c:
   r=c.execute('SELECT * FROM local_connect_requests WHERE id=?',(rid,)).fetchone()
   need(r is not None and r['expires']>=int(time.time()) and r['state']=='PENDING','Connection request expired or already handled; return to the website')
   c.execute('UPDATE local_connect_requests SET csrf_hash=? WHERE id=?',(hashed(csrf),rid))
  origin=html.escape(r['origin']);nonce=secrets.token_hex(16)
  page='''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Connect TRU Swap</title></head><body style="background:#16162a;color:white;font:18px system-ui;max-width:640px;margin:10vh auto;padding:24px"><h1>Connect your TRU Swap Agent</h1><p>Website: <strong>ORIGIN</strong></p><p>This website will be able to view and manage your swaps through this Agent. Wallet keys stay on this computer. Existing funding permissions still apply.</p><button id="approve">Approve connection</button> <button id="deny">Decline</button><p id="status" role="status"></p><script nonce="NONCE">async function decide(approve){document.querySelectorAll('button').forEach(b=>b.disabled=true);try{const r=await fetch('/v1/connect/decide',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({requestId:'RID',csrf:'CSRF',approve})});const x=await r.json();document.getElementById('status').textContent=r.ok?'Done. Return to the Market or Swap tab.':x.error;}catch(e){document.getElementById('status').textContent='Connection failed. Return to the website and retry.';}}document.getElementById('approve').onclick=()=>decide(true);document.getElementById('deny').onclick=()=>decide(false);</script></body></html>'''
  for k,v in [('ORIGIN',origin),('NONCE',nonce),('RID',rid),('CSRF',csrf)]:page=page.replace(k,v)
  return page.encode(),nonce
 def decide(self,rid,csrf,approve):
  need(type(approve) is bool and isinstance(csrf,str),'Invalid approval')
  with self.agent.store.connect() as c:
   c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT * FROM local_connect_requests WHERE id=?',(rid,)).fetchone()
   need(r and r['state']=='PENDING' and r['expires']>=int(time.time()),'Connection request expired or already handled')
   need(r['csrf_hash'] and hmac.compare_digest(r['csrf_hash'],hashed(csrf)),'Approval proof rejected')
   c.execute('UPDATE local_connect_requests SET state=?,csrf_hash=NULL WHERE id=?',('APPROVED' if approve else 'DENIED',rid));c.execute('COMMIT')
  return {'ok':True}
 def claim(self,origin,rid,proof):
  need(isinstance(proof,str) and re.fullmatch('[0-9a-f]{64}',proof),'Invalid browser proof')
  with self.agent.store.connect() as c:
   c.execute('BEGIN IMMEDIATE')
   r=c.execute('SELECT * FROM local_connect_requests WHERE id=?',(rid,)).fetchone()
   need(r and r['origin']==origin and r['expires']>=int(time.time()),'Connection request expired or origin differs')
   need(hmac.compare_digest(r['proof_hash'],hashed(proof)),'Browser proof rejected')
   if r['state']!='APPROVED':
    c.execute('COMMIT');return {'ok':True,'state':r['state']}
   seed=c.execute("SELECT v FROM local_connect_meta WHERE k='seed'").fetchone()[0]
   token=hmac.new(bytes.fromhex(seed),(rid+'|'+origin+'|'+proof).encode(),hashlib.sha256).hexdigest()
   now=int(time.time()*1000);expiry=now+self.agent.pair_ttl_seconds*1000
   c.execute('UPDATE local_connect_requests SET session_hash=? WHERE id=?',(hashed(token),rid))
   c.execute('''INSERT OR IGNORE INTO pair_sessions
    (token_hash,origin,created_ms,expires_ms,last_used_ms) VALUES(?,?,?,?,?)''',
    (hashed(token),origin,now,expiry,now))
   expiry=c.execute('SELECT expires_ms FROM pair_sessions WHERE token_hash=?',(hashed(token),)).fetchone()[0]
   c.execute('COMMIT')
  return {'ok':True,'state':'APPROVED','session':token,'expiresAt':expiry}
 def revoke(self,token):
  with self.agent.store.connect() as c:
   c.execute('BEGIN IMMEDIATE')
   c.execute("UPDATE local_connect_requests SET state='DENIED' WHERE session_hash=?",(hashed(token),))
   c.execute('DELETE FROM pair_sessions WHERE token_hash=?',(hashed(token),))
   c.execute('COMMIT')
 def handle_post(self,h,path,body):
  local=self.local(h);origin=h._origin()
  if path=='/v1/connect/decide':
   need(origin==local,'Approval must come from the local confirmation page')
   return self.decide(body.get('requestId'),body.get('csrf'),body.get('approve'))
  need(origin in self.agent.origins,'Website origin not allowed')
  if path=='/v1/connect/request':return self.request(origin,body.get('proofHash'))
  if path=='/v1/connect/claim':return self.claim(origin,body.get('requestId'),body.get('proof'))
  raise ConnectError('Unknown connection action')

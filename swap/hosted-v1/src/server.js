'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const T=require('./transactions'),{Store}=require('./store'),{Chain}=require('./chains'),{Coordinator}=require('./coordinator');
const {marketData}=require('./market-data');
function validateConfig(c){
  T.check(typeof c.enabled==='boolean'&&new URL(c.publicOrigin).origin===c.publicOrigin,'Set the exact public HTTPS origin');
  T.check(c.publicOrigin.startsWith('https://')||/^http:\/\/127\.0\.0\.1:\d+$/.test(c.publicOrigin),'HTTPS is required outside loopback');
  T.check(c.basePath==='/easy-swap/','Expected /easy-swap/ base path');
  T.check(Number.isInteger(c.firstSeconds)&&Number.isInteger(c.secondSeconds)&&c.firstSeconds-c.secondSeconds>=21600&&c.secondSeconds>=43200&&c.firstSeconds<=604800,'Unsafe refund intervals');
  T.check(c.claimSafetySeconds>=3600&&c.counterFundingSafetySeconds>=21600&&c.counterFundingSafetySeconds>c.claimSafetySeconds,'Unsafe funding/claim cutoff');
  T.check(Number.isInteger(c.maxActive)&&c.maxActive>0&&c.maxActive<=1000,'Invalid active limit');
  for(const name of ['tru','bsv','bsty']){const a=c.chains[name];T.check(a&&Number.isInteger(a.confirmations)&&a.confirmations>=1&&a.confirmations<=100,'Invalid confirmations');T.check(T.atoms(a.fundingFee)>=546n&&T.atoms(a.exitFee)>=546n,'Invalid fees');T.check(Number.isInteger(a.addressVersion)&&a.addressVersion>=0&&a.addressVersion<=255,'Invalid address version');if(c.enabled)T.hex(a.genesis,32);}
  for(const [pair,r] of Object.entries(c.rates)){T.check(['tru:bsv','bsv:tru','tru:bsty','bsty:tru'].includes(pair),'Unsupported rate');T.check(T.atoms(r.numerator)>0n&&T.atoms(r.denominator)>0n&&T.atoms(r.maxAtoms)>=T.atoms(r.minAtoms),'Invalid rate');}
}
function authenticate(store,path,body){
  const {auth,...payload}=body;T.check(auth&&Math.abs(Date.now()/1000-auth.time)<=60,'Request authorization expired');T.validPub(auth.pub);T.hex(auth.nonce,32);T.hex(auth.signature);
  const envelope={path,payload,time:auth.time,nonce:auth.nonce};T.check(T.verifyDigest(T.requestDigest(envelope),auth.signature,auth.pub),'Invalid request authorization');
  store.nonce(auth.pub+':'+auth.nonce,Math.ceil(auth.time+120),Math.floor(Date.now()/1000));return {user:auth.pub,payload};
}
async function checkNetworks(config,chains){for(const [name,chain] of Object.entries(chains)){const got=name==='tru'?(await chain.rpc('getblockbyheight',{height:1})).hash:await chain.rpc('getblockhash',[0]);T.check(got===config.chains[name].genesis,name+' network does not match the pinned genesis');await chain.tip();}}
function makeServer(config,store,coordinator){
  const queue=[];let processing=false;
  const drain=async()=>{if(processing)return;processing=true;while(queue.length){const task=queue.shift();try{task.resolve(await task.fn());}catch(e){task.reject(e);}}processing=false;};
  const serial=(fn,priority=false)=>new Promise((resolve,reject)=>{if(!priority&&queue.length>=16)return reject(new Error('Service busy; retry shortly'));const task={fn,resolve,reject};priority?queue.unshift(task):queue.push(task);void drain();});
  const limits=new Map();
  const server=http.createServer(async(req,res)=>{
    res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Cache-Control','no-store');
    const reply=(code,value)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(value));};
    try{
      const forwarded=req.headers['x-real-ip'];const ip=config.trustProxy&&typeof forwarded==='string'&&/^[0-9a-fA-F:.]{3,50}$/.test(forwarded)?forwarded:req.socket.remoteAddress,bucket=Math.floor(Date.now()/60000),prior=limits.get(ip);if(!prior||prior.bucket!==bucket)limits.set(ip,{bucket,count:0});T.check(++limits.get(ip).count<=180,'Request limit reached');if(limits.size>10000)for(const [k,v]of limits)if(v.bucket!==bucket)limits.delete(k);
      const route=new URL(req.url,'http://localhost').pathname;T.check(route.startsWith(config.basePath),'Unknown route');const local=route.slice(config.basePath.length);
      if(req.method==='GET'&&local==='api/config')return reply(200,coordinator.publicConfig());
      if(req.method==='GET'&&local==='api/markets')return reply(200,marketData(store));
      const staticFiles={'':'index.html','index.html':'index.html','app.js':'app.js','style.css':'style.css'};
      if(req.method==='GET'&&Object.hasOwn(staticFiles,local)){res.setHeader('Content-Type',local.endsWith('.js')?'text/javascript':local.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(path.join(__dirname,'../public',staticFiles[local])));return;}
      T.check(req.method==='POST'&&['api/balance','api/quote','api/fund','api/claim','api/swaps','api/swap','api/withdraw'].includes(local),'Unknown endpoint');
      T.check(req.headers.origin===config.publicOrigin,'Request origin does not match');T.check((req.headers['content-type']||'').split(';')[0]==='application/json','JSON request required');
      let size=0,chunks=[];for await(const chunk of req){size+=chunk.length;T.check(size<=500000,'Request body limit');chunks.push(chunk);}const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const result=await serial(async()=>{const {user,payload:b}=authenticate(store,route,body);switch(local){
        case 'api/balance':T.check(['tru','bsv','bsty'].includes(b.chain),'Unsupported chain');return {coins:await coordinator.chains[b.chain].coins(user)};
        case 'api/quote':return coordinator.view(await coordinator.quote(user,b));
        case 'api/fund':return coordinator.view(await coordinator.submitFunding(user,b));
        case 'api/claim':return coordinator.view(await coordinator.claim(user,b));
        case 'api/withdraw':return coordinator.withdraw(user,b);
        case 'api/swaps':return store.all(user).map(r=>coordinator.view(r));
        case 'api/swap':return coordinator.view(coordinator.owned(user,b.id));
      }});reply(200,result);
    }catch(e){reply(400,{error:e.code==='SQLITE_CONSTRAINT_PRIMARYKEY'?'Request already used':String(e.message).slice(0,240)});}
  });
  server.requestTimeout=30000;server.headersTimeout=15000;let running=false;
  const timer=setInterval(()=>{if(running)return;running=true;serial(()=>coordinator.tick(),true).catch(()=>{}).finally(()=>{running=false;});},15000);timer.unref();server.on('close',()=>clearInterval(timer));return server;
}
async function main(){
  process.umask(0o077);const config=JSON.parse(fs.readFileSync(process.argv[2]||'config.json','utf8'));validateConfig(config);
  fs.mkdirSync(config.stateDir,{recursive:true,mode:0o700});const st=fs.statSync(config.operatorKeyFile);T.check((st.mode&0o077)===0,'Operator key file must have mode 0600');const key=fs.readFileSync(config.operatorKeyFile,'utf8').trim();T.hex(key,32);
  const chains=Object.fromEntries(Object.entries(config.chains).map(([k,v])=>[k,new Chain(k,v)]));
  const store=new Store(path.join(config.stateDir,'swaps.sqlite'));if(config.enabled||store.all().some(r=>r.userFunding))await checkNetworks(config,chains);
  const c=new Coordinator(config,store,chains,key),server=makeServer(config,store,c);
  server.listen(config.port,'127.0.0.1',()=>console.log('Hosted swap listening on loopback port '+config.port+'; new swaps '+(config.enabled?'enabled':'paused')));
  for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>server.close(()=>{store.close();process.exit(0);}));
}
if(require.main===module)main().catch(e=>{console.error(e.message);process.exitCode=1;});
module.exports={validateConfig,authenticate,checkNetworks,makeServer};

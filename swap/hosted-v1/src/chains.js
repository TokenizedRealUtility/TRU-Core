'use strict';
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const tls=require('node:tls'),net=require('node:net');
const run=promisify(execFile), T=require('./transactions');
class RpcError extends Error { constructor(chain,method,code){super(chain+' node could not complete '+method);this.code=code;}}
class Chain {
  constructor(name,config){this.name=name;this.config=config;T.check(Array.isArray(config.cli)&&config.cli.length,'Node CLI configuration missing');}
  async rpc(method,params){
    const args=this.name==='tru'?['-json','raw',method,JSON.stringify(params||{})]:[method,...(params||[]).map(x=>typeof x==='string'?x:JSON.stringify(x))];
    let out;
    try{out=(await run(this.config.cli[0],[...this.config.cli.slice(1),...args],{timeout:20000,maxBuffer:16*1024*1024,windowsHide:true})).stdout.trim();}
    catch(e){const m=String(e.stderr||'').match(/error code:\s*(-?\d+)/i);throw new RpcError(this.name,method,m?Number(m[1]):null);}
    let result;try{result=JSON.parse(out);}catch{result=out;}
    if(result&&typeof result==='object'&&result.error)throw new RpcError(this.name,method,result.error.code);
    return result&&typeof result==='object'&&Object.hasOwn(result,'result')?result.result:result;
  }
  async electrum(method,script){
    const c=this.config.electrum;T.check(c&&c.host&&c.port,'An Electrum indexer must be configured for '+this.name);
    const scriptHash=T.hash(T.Buffer.from(script,'hex')).reverse().toString('hex');
    return await new Promise((resolve,reject)=>{
      let data='',done=false;const socket=c.tls===false?net.connect(c.port,c.host):tls.connect({host:c.host,port:c.port,servername:c.servername||c.host,rejectUnauthorized:true});
      const finish=(e,v)=>{if(done)return;done=true;socket.destroy();e?reject(e):resolve(v);};
      socket.setTimeout(15000,()=>finish(new Error('Indexer timed out')));socket.on('error',()=>finish(new Error('Indexer unavailable')));
      socket.once(c.tls===false?'connect':'secureConnect',()=>socket.write(JSON.stringify({jsonrpc:'2.0',id:1,method,params:[scriptHash]})+'\n'));
      socket.on('data',b=>{data+=b.toString();if(data.length>2*1024*1024)return finish(new Error('Indexer response limit'));const n=data.indexOf('\n');if(n<0)return;try{const v=JSON.parse(data.slice(0,n));T.check(v.id===1&&!v.error&&Array.isArray(v.result),'Invalid indexer result');finish(null,v.result);}catch(e){finish(e);}});
      socket.on('end',()=>finish(new Error('Indexer closed connection')));
    });
  }
  async status(id){
    T.hex(id,32);let r;
    try{r=await this.rpc(this.name==='tru'?'gettransaction':'getrawtransaction',this.name==='tru'?{txid:id}:[id,true]);}
    catch(e){if(e instanceof RpcError&&e.code===-5)return {known:false,confirmations:0};throw e;}
    if(this.name==='tru')return {known:r.txState==='MEMPOOL'||(r.active&&r.txState==='CONFIRMED'),confirmations:r.active&&r.txState==='CONFIRMED'?r.confirmations:0,raw:r.hex||null,block:r.blockhash||null};
    let conf=0;if(r.blockhash){const h=await this.rpc('getblockheader',[r.blockhash,true]);conf=Math.max(0,Number(h.confirmations||0));}
    let known=conf>0;if(!known){try{await this.rpc('getmempoolentry',[id]);known=true;}catch(e){if(!(e instanceof RpcError&&e.code===-5))throw e;}}
    return {known,confirmations:conf,raw:r.hex,block:r.blockhash||null};
  }
  async outpoint(id,vout){
    const r=await this.rpc('gettxout',this.name==='tru'?{txid:id,n:vout,includeMempool:true}:[id,vout,true]);if(!r)return null;
    const s=await this.status(id);if(!s.raw)return null;
    // TRU gettxout reports a placeholder confirmation count; never use it.
    const tx=T.parse(this.name,s.raw),o=tx.outputs[vout];T.check(o&&o.script===r.scriptPubKey.hex,'Prevout script mismatch');
    return {txid:id,vout,amount:o.amount,script:o.script,confirmations:s.confirmations,coinbase:!!r.coinbase};
  }
  async coins(pub){
    const script=T.p2pkh(pub);let candidates;
    if(this.name==='tru')candidates=(await this.rpc('listunspentWeb',{address:T.address(pub,this.config.addressVersion)})).filter(x=>x.spendable&&!x.isTokenControl).map(x=>({txid:x.txid,vout:x.vout}));
    else candidates=(await this.electrum('blockchain.scripthash.listunspent',script)).filter(x=>x.height>0).map(x=>({txid:x.tx_hash,vout:x.tx_pos}));
    T.check(candidates.length<=500,'Wallet has too many outputs; consolidate first');const out=[];
    for(const c of candidates){const u=await this.outpoint(c.txid,c.vout);if(u&&u.script===script&&u.confirmations>=this.config.confirmations&&(!u.coinbase||u.confirmations>=101))out.push(u);}
    return out.sort((a,b)=>a.txid.localeCompare(b.txid)||a.vout-b.vout);
  }
  async tip(){
    if(this.name!=='tru'){const i=await this.rpc('getblockchaininfo',[]);const h=await this.rpc('getblockheader',[i.bestblockhash,true]);T.check(!i.initialblockdownload,'Node still synchronizing');return {height:i.blocks,hash:i.bestblockhash,mtp:h.mediantime,time:h.time};}
    const i=await this.rpc('getchaininfo',{});T.check(i.chainValid,'TRU chain validation unavailable');let hash=i.bestHash,times=[];
    for(let n=0;n<11&&hash;n++){const b=await this.rpc('getblock',{hash});times.push(b.timestamp);hash=b.prevhash;if(/^0+$/.test(hash))break;}
    T.check(times.length>0,'Missing TRU timestamps');const time=times[0];times.sort((a,b)=>a-b);return {height:i.bestHeight,hash:i.bestHash,mtp:times[Math.floor(times.length/2)],time};
  }
  async broadcast(raw){const id=T.txid(this.name,raw);const prior=await this.status(id);if(prior.known)return id;
    const r=await this.rpc('sendrawtransaction',this.name==='tru'?{txHex:raw}:[raw]);const got=typeof r==='string'?r:r.txid;T.check(got===id,'Node transaction ID mismatch');return id;
  }
  async findSpend(id,vout,script,fromHeight){
    let ids=[];
    if(this.name!=='tru')ids=(await this.electrum('blockchain.scripthash.get_history',script)).map(x=>x.tx_hash);
    else {
      const tip=await this.tip();T.check(tip.height-fromHeight<=this.config.maxRecoveryScanBlocks,'Recovery scan exceeds configured bound; operator must increase maxRecoveryScanBlocks');
      for(let h=Math.max(1,fromHeight);h<=tip.height;h++){const b=await this.rpc('getblockbyheight',{height:h});ids.push(...b.tx);}
      const mem=await this.rpc('getrawmempool',{});ids.push(...(Array.isArray(mem)?mem:Object.keys(mem)));
    }
    for(const candidate of [...new Set(ids)]){if(candidate===id)continue;const s=await this.status(candidate);if(!s.known||!s.raw)continue;let tx;try{tx=T.parse(this.name,s.raw);}catch{continue;}if(tx.inputs.some(x=>x.txid===id&&x.vout===vout))return {...s,id:candidate};}
    return null;
  }
}
module.exports={Chain,RpcError};

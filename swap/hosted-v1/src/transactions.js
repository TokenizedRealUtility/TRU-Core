'use strict';
// Shared, deterministic transaction code. No RPC, DOM or private-key storage.
const bsv = require('@scrypt-inc/bsv');
const {Buffer} = require('buffer');
const artifact = require('../artifacts/HostedHTLC.json');
const B = h => Buffer.from(h, 'hex');
const hash = b => bsv.crypto.Hash.sha256(b);
const doubleHash = b => hash(hash(b));
const h160 = h => bsv.crypto.Hash.sha256ripemd160(B(h)).toString('hex');
function check(ok, message) { if (!ok) throw new Error(message); }
function hex(h, bytes) { check(typeof h === 'string' && /^[0-9a-f]*$/.test(h) && h.length % 2 === 0 && (!bytes || h.length === bytes * 2), 'Invalid hex'); return h; }
function atoms(s) { check(typeof s === 'string' && /^(0|[1-9][0-9]*)$/.test(s), 'Use integer atom strings'); const n=BigInt(s); check(n<=9007199254740991n,'Amount exceeds supported range'); return n; }
function le(n, bytes) { n=BigInt(n);check(n>=0n && n<(1n<<BigInt(bytes*8)),'Integer overflow');const b=Buffer.alloc(bytes);for(let i=0;i<bytes;i++){b[i]=Number(n&255n);n>>=8n;}return b.toString('hex'); }
function vi(n) { check(Number.isSafeInteger(n)&&n>=0,'Invalid length');return n<253?le(n,1):n<=65535?'fd'+le(n,2):'fe'+le(n,4); }
function push(h) { hex(h);const n=h.length/2;return (n<76?le(n,1):n<256?'4c'+le(n,1):'4d'+le(n,2))+h; }
function scriptNum(n) { check(Number.isSafeInteger(n)&&n>=0,'Invalid script number');if(!n)return '00';if(n<=16)return le(0x50+n,1);let h='';while(n){h+=le(n%256,1);n=Math.floor(n/256);}if(parseInt(h.slice(-2),16)&128)h+='00';return push(h); }
function pubkey(privateHex) { return new bsv.PrivateKey(hex(privateHex,32)).publicKey.toString(); }
function validPub(p) { hex(p,33);check(/^0[23]/.test(p),'Compressed public key required');new bsv.PublicKey(p);return p; }
function p2pkh(p) { validPub(p);return '76a914'+h160(p)+'88ac'; }
function address(p, version) { check(Number.isInteger(version)&&version>=0&&version<=255,'Invalid network version');return bsv.encoding.Base58Check.encode(Buffer.concat([Buffer.from([version]),B(h160(validPub(p)))])); }
function contract(chain, c) {
  check(['tru','bsv','bsty'].includes(chain),'Unsupported chain');validPub(c.claim);validPub(c.refund);check(c.claim!==c.refund,'Role keys must differ');hex(c.hash,20);
  check(Number.isInteger(c.time)&&c.time>=500000000&&c.time<=2147483647,'Invalid refund timestamp');
  if(chain==='bsv') return artifact.hex.replace('<claimKey>',push(c.claim)).replace('<refundKey>',push(c.refund)).replace('<secretHash>',push(c.hash)).replace('<refundTime>',scriptNum(c.time));
  return '63a914'+c.hash+'8821'+c.claim+'ac67'+scriptNum(c.time)+'b17521'+c.refund+'ac68';
}
function locking(chain,c) { const s=contract(chain,c);return chain==='bsty'?'a914'+h160(s)+'87':s; }
function serialize(chain,tx,scripts) {
  check(tx.inputs.length>0&&tx.inputs.length<=100&&tx.outputs.length>0&&tx.outputs.length<=10,'Transaction size limit');
  return le(tx.version,4)+vi(tx.inputs.length)+tx.inputs.map((i,j)=>{
    const id=B(hex(i.txid,32));const sig=hex(scripts?scripts[j]:(i.script||''));
    return (chain==='tru'?id:id.reverse()).toString('hex')+le(i.vout,4)+vi(sig.length/2)+sig+le(i.sequence,4);
  }).join('')+vi(tx.outputs.length)+tx.outputs.map(o=>le(atoms(o.amount),8)+vi(hex(o.script).length/2)+o.script).join('')+le(tx.locktime,4)+(chain==='tru'?'00':'');
}
function parse(chain,raw) {
  hex(raw);check(raw.length<=400000,'Transaction too large');let p=0;
  function take(n){check(p+n*2<=raw.length,'Truncated transaction');const h=raw.slice(p,p+n*2);p+=n*2;return h;}
  function num(n){return BigInt('0x'+B(take(n)).reverse().toString('hex'));}
  function size(){const n=Number(num(1));check(n!==255,'Oversized varint');const v=n<253?n:Number(num(n===253?2:4));check(v<=100000,'Oversized field');check(n<253 || v>=(n===253?253:65536),'Noncanonical varint');return v;}
  const tx={version:Number(num(4)),inputs:[],outputs:[],locktime:0};const witness=chain==='bsty'&&raw.slice(p,p+4)==='0001';if(witness)take(2);let n=size();check(n>0&&n<=100,'Input limit');
  while(n--){let id=B(take(32));if(chain!=='tru')id=id.reverse();tx.inputs.push({txid:id.toString('hex'),vout:Number(num(4)),script:take(size()),sequence:Number(num(4))});}
  n=size();check(n>0&&n<=10000,'Output limit');while(n--)tx.outputs.push({amount:num(8).toString(),script:take(size())});if(witness)for(const input of tx.inputs){let items=size();check(items<=100,'Witness limit');while(items--)take(size());}tx.locktime=Number(num(4));
  if(chain==='tru')check(take(1)==='00','Token metadata is not supported for swaps');check(p===raw.length,'Trailing transaction data');return tx;
}
function txid(chain,raw) {const tx=parse(chain,raw);let d=doubleHash(B(chain==='tru'?serialize(chain,tx,tx.inputs.map(()=>'')):raw));return (chain==='tru'?d:d.reverse()).toString('hex');}
function preimage(chain,tx,index,script,amount) {
  if(chain!=='bsv'){const scripts=tx.inputs.map(()=> '');scripts[index]=script;return serialize(chain,tx,scripts)+'01000000';}
  const t=new bsv.Transaction(serialize(chain,tx));return bsv.Transaction.Sighash.sighashPreimage(t,0x41,index,bsv.Script.fromHex(script),new bsv.crypto.BN(amount)).toString('hex');
}
function signDigest(digest,key) {return bsv.crypto.ECDSA.sign(B(hex(digest,32)),new bsv.PrivateKey(hex(key,32))).toDER().toString('hex');}
function verifyDigest(digest,sig,pub) {try{return bsv.crypto.ECDSA.verify(B(hex(digest,32)),bsv.crypto.Signature.fromDER(B(hex(sig))),new bsv.PublicKey(validPub(pub)));}catch{return false;}}
function sigFor(chain,tx,index,script,amount,key) {return signDigest(doubleHash(B(preimage(chain,tx,index,script,amount))).toString('hex'),key)+(chain==='bsv'?'41':'01');}
function funding(chain,coins,c,amount,fee,owner) {
  validPub(owner);check(atoms(amount)>0n&&atoms(fee)>0n,'Amount/fee must be positive');check(coins.length>0&&coins.length<=100,'Input limit');
  const seen=new Set();let total=0n;for(const i of coins){hex(i.txid,32);check(!seen.has(i.txid+':'+i.vout),'Duplicate input');seen.add(i.txid+':'+i.vout);check(i.script===p2pkh(owner),'Wrong input owner');total+=atoms(i.amount);}
  const change=total-atoms(amount)-atoms(fee);check(change>=0n,'Insufficient confirmed funds');
  const outputs=chain==='tru'?[{amount:'0',script:'6a'+push(Buffer.from('TRU_CONTRACT:HTLC_Atomic_Swap_V1').toString('hex'))}]:[];
  outputs.push({amount,script:locking(chain,c)});if(change>0n)outputs.push({amount:change.toString(),script:p2pkh(owner)});
  return {version:1,inputs:coins.map(i=>({txid:i.txid,vout:i.vout,sequence:0xffffffff,script:''})),outputs,locktime:0};
}
function signFunding(chain,tx,coins,key) {
  const pub=pubkey(key);check(coins.length===tx.inputs.length,'Prevout count mismatch');
  const scripts=coins.map((u,i)=>{check(tx.inputs[i].txid===u.txid&&tx.inputs[i].vout===u.vout&&u.script===p2pkh(pub),'Prevout mismatch');return push(sigFor(chain,tx,i,u.script,u.amount,key))+push(pub);});return serialize(chain,tx,scripts);
}
function exit(chain,fundingId,c,amount,fee,recipient,refund=false) {
  const value=atoms(amount)-atoms(fee);check(value>=546n,'Contract value cannot pay exit fee');validPub(recipient);
  return {version:1,inputs:[{txid:hex(fundingId,32),vout:chain==='tru'?1:0,sequence:refund?0xfffffffe:0xffffffff,script:''}],outputs:[{amount:value.toString(),script:p2pkh(recipient)}],locktime:refund?c.time:0};
}
function signExit(chain,tx,c,amount,key,secret=null) {
  const refund=secret===null;check(pubkey(key)===(refund?c.refund:c.claim),'Wrong contract role');const s=contract(chain,c);const sig=sigFor(chain,tx,0,s,amount,key);
  let script;
  if(chain==='bsv')script=refund?push(sig)+push(preimage(chain,tx,0,s,amount))+'51':push(sig)+push(hex(secret,32))+'00';
  else script=refund?push(sig)+'00':push(sig)+push(hex(secret,32))+'51';
  if(chain==='bsty')script+=push(s);
  if(!refund)check(h160(secret)===c.hash,'Wrong secret');return serialize(chain,tx,[script]);
}
function sameIntent(chain,raw,expected) {const parsed=parse(chain,raw);return serialize(chain,parsed)===raw&&serialize(chain,parsed,expected.inputs.map(()=>''))===serialize(chain,expected,expected.inputs.map(()=>''));}
function pushes(script) {const s=bsv.Script.fromHex(hex(script));return s.chunks.filter(c=>c.buf).map(c=>c.buf.toString('hex'));}
function verifySig(chain,tx,index,script,amount,sig,pub) {
  check(sig.slice(-2)===(chain==='bsv'?'41':'01'),'Only SIGHASH_ALL is allowed');
  const der=sig.slice(0,-2);check(bsv.crypto.Signature.fromDER(B(der)).hasLowS(),'High-S signature');
  check(verifyDigest(doubleHash(B(preimage(chain,tx,index,script,amount))).toString('hex'),der,pub),'Invalid signature');
}
function verifyFunding(chain,raw,expected,coins,pub) {
  check(sameIntent(chain,raw,expected),'Funding transaction changed');const tx=parse(chain,raw);
  tx.inputs.forEach((input,i)=>{const p=pushes(input.script);check(p.length===2&&p[1]===pub&&input.script===push(p[0])+push(pub),'Invalid funding unlock');verifySig(chain,tx,i,coins[i].script,coins[i].amount,p[0],pub);});return true;
}
function verifyExit(chain,raw,expected,c,amount,refund) {
  check(sameIntent(chain,raw,expected),'Exit transaction changed');const tx=parse(chain,raw),p=pushes(tx.inputs[0].script),s=contract(chain,c);check(p.length>0,'Missing exit signature');
  let expectedScript=push(p[0]);if(refund)expectedScript+=chain==='bsv'?push(preimage(chain,tx,0,s,amount))+'51':'00';
  else {check(p[1]&&p[1].length===64&&h160(p[1])===c.hash,'Invalid claim secret');expectedScript+=push(p[1])+(chain==='bsv'?'00':'51');}
  if(chain==='bsty')expectedScript+=push(s);check(tx.inputs[0].script===expectedScript,'Exit unlocking script changed');
  verifySig(chain,tx,0,s,amount,p[0],refund?c.refund:c.claim);return true;
}
function extractSecret(raw,chain,h) {for(const i of parse(chain,raw).inputs)for(const p of pushes(i.script))if(p.length===64&&h160(p)===h)return p;return null;}
function canonical(value) {if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';return JSON.stringify(value);}
function requestDigest(envelope) {return hash(Buffer.from('TRU-HOSTED-SWAP-AUTH-V1\0'+canonical(envelope))).toString('hex');}
module.exports={bsv,Buffer,check,hex,atoms,le,vi,push,hash,doubleHash,h160,pubkey,validPub,p2pkh,address,contract,locking,serialize,parse,txid,preimage,signDigest,verifyDigest,funding,signFunding,exit,signExit,sameIntent,verifyFunding,verifyExit,extractSecret,canonical,requestDigest};

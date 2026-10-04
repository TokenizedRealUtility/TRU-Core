'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const T=require('../src/transactions'),scrypt=require('scryptlib');
const a='01'.padStart(64,'0'),b='02'.padStart(64,'0'),secret='ab'.repeat(32);
const c={claim:T.pubkey(a),refund:T.pubkey(b),hash:T.h160(secret),time:1800000000};
function bsvVerify(raw,contract=c){const I=T.bsv.Script.Interpreter;I.MAX_SCRIPT_ELEMENT_SIZE=Number.MAX_SAFE_INTEGER;I.MAXIMUM_ELEMENT_SIZE=Number.MAX_SAFE_INTEGER;const i=new I();let flags=scrypt.DEFAULT_FLAGS & ~I.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY & ~I.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY & ~I.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;return i.verify(T.bsv.Script.fromHex(T.parse('bsv',raw).inputs[0].script),T.bsv.Script.fromHex(T.contract('bsv',contract)),new T.bsv.Transaction(raw),0,flags,new T.bsv.crypto.BN(100000));}
for(const chain of ['tru','bsv','bsty']){
 test(chain+' funding roundtrip, signature, fixed intent, metadata and ID',()=>{
  const coins=[{txid:'10'.repeat(32),vout:3,amount:'500000',script:T.p2pkh(c.refund)},{txid:'20'.repeat(32),vout:4,amount:'100000',script:T.p2pkh(c.refund)}];
  const plan=T.funding(chain,coins,c,'200000','10000',c.refund),raw=T.signFunding(chain,plan,coins,b);
  assert(T.verifyFunding(chain,raw,plan,coins,c.refund));assert.equal(T.serialize(chain,T.parse(chain,raw)),raw);
  const modified=T.parse(chain,raw);modified.outputs.at(-1).amount='399999';assert.throws(()=>T.verifyFunding(chain,T.serialize(chain,modified),plan,coins,c.refund));
  if(chain==='tru'){assert.equal(plan.outputs[1].script.length,206);assert.equal(T.txid(chain,raw),T.txid(chain,T.serialize(chain,plan)));assert.equal(plan.outputs[0].script,'6a205452555f434f4e54524143543a48544c435f41746f6d69635f537761705f5631');}
  else assert.notEqual(T.txid(chain,raw),T.txid(chain,T.serialize(chain,plan)));
 });
 test(chain+' claim and refund use separate roles and enforced fields',()=>{
  for(const refund of [false,true]){const plan=T.exit(chain,'66'.repeat(32),c,'100000','10000',refund?c.refund:c.claim,refund);const raw=T.signExit(chain,plan,c,'100000',refund?b:a,refund?null:secret);assert(T.verifyExit(chain,raw,plan,c,'100000',refund));assert.throws(()=>T.signExit(chain,plan,c,'100000',refund?a:b,refund?null:secret));const changed=T.parse(chain,raw);changed.outputs[0].amount='89999';assert.throws(()=>T.verifyExit(chain,T.serialize(chain,changed),plan,c,'100000',refund));}
 });
}
test('BSV compiled constructor parity and script execution without CLTV/CSV flags',()=>{
 const C=scrypt.buildContractClass(require('../artifacts/HostedHTLC.json')),instance=new C(scrypt.PubKey(c.claim),scrypt.PubKey(c.refund),scrypt.Ripemd160(c.hash),BigInt(c.time));assert.equal(T.contract('bsv',c),instance.lockingScript.toHex());
 for(const refund of [false,true]){const plan=T.exit('bsv','66'.repeat(32),c,'100000','1000',refund?c.refund:c.claim,refund),raw=T.signExit('bsv',plan,c,'100000',refund?b:a,refund?null:secret);assert(bsvVerify(raw));}
});
test('BSV refuses early refund, final sequence and forged preimage even with valid role signature',()=>{
 for(const mutation of [p=>p.locktime--,p=>p.inputs[0].sequence=0xffffffff]){let p=T.exit('bsv','66'.repeat(32),c,'100000','1000',c.refund,true);mutation(p);assert.equal(bsvVerify(T.signExit('bsv',p,c,'100000',b)),false);}
 const p=T.exit('bsv','66'.repeat(32),c,'100000','1000',c.refund,true),raw=T.signExit('bsv',p,c,'100000',b),tx=T.parse('bsv',raw);tx.locktime--;assert.equal(bsvVerify(T.serialize('bsv',tx)),false);
 const wrong={...c,hash:T.h160('cd'.repeat(32))};assert.equal(bsvVerify(T.signExit('bsv',T.exit('bsv','66'.repeat(32),c,'100000','1000',c.claim),c,'100000',a,secret),wrong),false);
});
test('BSTY P2SH claim executes with legacy SIGHASH_ALL',()=>{
 const plan=T.exit('bsty','66'.repeat(32),c,'100000','1000',c.claim),raw=T.signExit('bsty',plan,c,'100000',a,secret),I=T.bsv.Script.Interpreter,i=new I();const flags=I.SCRIPT_VERIFY_P2SH|I.SCRIPT_VERIFY_DERSIG|I.SCRIPT_VERIFY_LOW_S|I.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;assert(i.verify(T.bsv.Script.fromHex(T.parse('bsty',raw).inputs[0].script),T.bsv.Script.fromHex(T.locking('bsty',c)),new T.bsv.Transaction(raw),0,flags,new T.bsv.crypto.BN(100000)),i.errstr);
});
test('Rejects duplicate inputs, insufficient value, unsafe timestamps and trailing bytes',()=>{
 const coin={txid:'aa'.repeat(32),vout:0,amount:'100000',script:T.p2pkh(c.refund)};assert.throws(()=>T.funding('tru',[coin,coin],c,'100','1',c.refund));assert.throws(()=>T.funding('tru',[coin],c,'100000','1',c.refund));assert.throws(()=>T.contract('tru',{...c,time:499999999}));assert.throws(()=>T.parse('tru',T.serialize('tru',T.exit('tru','aa'.repeat(32),c,'10000','1000',c.claim))+'00'));
});
test('BSTY can read a funding prevout from a witness transaction',()=>{
 const p=T.exit('bsty','11'.repeat(32),c,'10000','1000',c.claim),raw=T.serialize('bsty',p),witness=raw.slice(0,8)+'0001'+raw.slice(8,-8)+'0101ab'+raw.slice(-8);assert.equal(T.parse('bsty',witness).outputs[0].amount,'9000');assert.equal(T.sameIntent('bsty',witness,p),false);
});

'use strict';
const T=require('./transactions');
const terminal=new Set(['EXPIRED','COMPLETE','REFUNDED']);
const now=()=>Math.floor(Date.now()/1000);
function select(coins,target){let total=0n,out=[];for(const u of coins){out.push(u);total+=T.atoms(u.amount);if(total>=target&&(total===target||total-target>=546n))return out;if(out.length>=100)break;}throw new Error('Insufficient confirmed liquidity, including fees');}
class Coordinator {
  constructor(config,store,chains,operatorKey){this.config=config;this.store=store;this.chains=chains;this.key=operatorKey;this.operator=T.pubkey(operatorKey);for(const r of store.all())if(r.userFunding)T.check(r.operator===this.operator,'Operator key does not match the existing swap journal');}
  publicConfig(){return {protocol:'TRU-HOSTED-SWAP-V1',enabled:this.config.enabled,operator:this.operator,rates:this.config.rates,chains:Object.fromEntries(Object.entries(this.config.chains).map(([k,v])=>[k,{addressVersion:v.addressVersion,confirmations:v.confirmations,fundingFee:v.fundingFee,exitFee:v.exitFee}])),firstSeconds:this.config.firstSeconds,secondSeconds:this.config.secondSeconds};}
  owned(user,id){const r=this.store.get(id);T.check(r&&r.user===user,'Swap not found');return r;}
  async quote(user,b){
    T.check(this.config.enabled,'New swaps are paused');T.validPub(user);T.check(user!==this.operator,'Use a separate user wallet');
    T.check(['tru:bsv','bsv:tru','tru:bsty','bsty:tru'].includes(b.from+':'+b.to),'Unsupported pair');
    T.hex(b.hash,20);T.hex(b.requestId,32);const prior=this.store.get(b.requestId);
    if(prior){T.check(prior.user===user&&prior.from===b.from&&prior.to===b.to&&prior.amount===b.amount&&prior.hash===b.hash,'Request ID already used');return prior;}
    const existing=this.store.all();T.check(existing.filter(r=>!terminal.has(r.state)).length<this.config.maxActive,'Swap service is busy');T.check(existing.filter(r=>r.user===user&&!terminal.has(r.state)).length<3,'Finish or expire your existing swaps first');
    const rate=this.config.rates[b.from+':'+b.to];T.check(rate&&rate.enabled,'This direction is paused');const amount=T.atoms(b.amount);
    T.check(amount>=T.atoms(rate.minAtoms)&&amount<=T.atoms(rate.maxAtoms),'Amount is outside the quote limits');
    const receive=amount*T.atoms(rate.numerator)/T.atoms(rate.denominator),outFee=this.config.chains[b.to].exitFee;
    T.check(receive>T.atoms(outFee)+546n,'Receive amount cannot pay the claim fee');T.check(amount>T.atoms(this.config.chains[b.from].exitFee)+546n,'Input amount cannot pay the refund fee');
    const firstTip=await this.chains[b.from].tip(),secondTip=await this.chains[b.to].tip(),time=now();
    for(const tip of [firstTip,secondTip])T.check(tip.time>time-this.config.maxTipAge&&tip.mtp<time+7200,'A chain is not ready for swaps');
    const userCoins=select(await this.chains[b.from].coins(user),amount+T.atoms(this.config.chains[b.from].fundingFee));
    const ownCoins=select((await this.chains[b.to].coins(this.operator)).filter(u=>!this.store.reserved(b.to,u)),receive+T.atoms(this.config.chains[b.to].fundingFee));
    const r={version:1,id:b.requestId,user,operator:this.operator,from:b.from,to:b.to,amount:b.amount,receive:receive.toString(),hash:b.hash,created:time,expires:time+300,state:'QUOTED',firstHeight:firstTip.height,secondHeight:secondTip.height,
      first:{claim:this.operator,refund:user,hash:b.hash,time:time+this.config.firstSeconds},second:{claim:user,refund:this.operator,hash:b.hash,time:time+this.config.secondSeconds},
      fees:{firstFunding:this.config.chains[b.from].fundingFee,secondFunding:this.config.chains[b.to].fundingFee,firstExit:this.config.chains[b.from].exitFee,secondExit:outFee},userCoins,ownCoins};
    r.userPlan=T.funding(r.from,userCoins,r.first,r.amount,r.fees.firstFunding,user);
    this.store.transaction(()=>{this.store.put(r);this.store.reserve(r,r.to,ownCoins);this.store.reserve(r,r.from,userCoins);});return r;
  }
  async submitFunding(user,b){const r=this.owned(user,b.id);
    if(r.userFunding){T.check(b.raw===r.userFunding&&b.refund===r.userRefund,'Funding already fixed');return r;}
    T.check(this.config.enabled&&r.state==='QUOTED'&&now()<r.expires,'Quote expired or funding is paused');
    T.verifyFunding(r.from,b.raw,r.userPlan,r.userCoins,user);const id=T.txid(r.from,b.raw);
    const refund=T.exit(r.from,id,r.first,r.amount,r.fees.firstExit,user,true);T.verifyExit(r.from,b.refund,refund,r.first,r.amount,true);
    for(const u of r.userCoins){const live=await this.chains[r.from].outpoint(u.txid,u.vout);T.check(live&&live.script===u.script&&live.amount===u.amount&&live.confirmations>=this.config.chains[r.from].confirmations,'Funding input changed');}
    // Durable signed bytes and enforceable refund BEFORE the first network call.
    r.userFunding=b.raw;r.userFundingId=id;r.userRefund=b.refund;r.userRefundId=T.txid(r.from,b.refund);r.state='FUNDING';this.store.put(r);
    await this.chains[r.from].broadcast(r.userFunding);return r;
  }
  async claim(user,b){const r=this.owned(user,b.id);T.check(r.ownFunding,'Counter-funding is not ready');
    const [a,c,tip]=await Promise.all([this.chains[r.from].status(r.userFundingId),this.chains[r.to].status(r.ownFundingId),this.chains[r.to].tip()]);
    T.check(a.confirmations>=this.config.chains[r.from].confirmations&&c.confirmations>=this.config.chains[r.to].confirmations,'Both funding transactions must be confirmed');
    T.check(tip.mtp<r.second.time-this.config.claimSafetySeconds,'Too close to the counterparty refund deadline');
    const expected=T.exit(r.to,r.ownFundingId,r.second,r.receive,r.fees.secondExit,user,false);T.verifyExit(r.to,b.raw,expected,r.second,r.receive,false);
    if(r.userClaim)T.check(r.userClaim===b.raw,'Claim already fixed');r.userClaim=b.raw;r.userClaimId=T.txid(r.to,b.raw);r.state='CLAIMING';this.store.put(r);
    await this.chains[r.to].broadcast(r.userClaim);return r;
  }
  async prepareCounter(r){
    for(const u of r.ownCoins){const live=await this.chains[r.to].outpoint(u.txid,u.vout);T.check(live&&live.script===u.script&&live.amount===u.amount&&live.confirmations>=this.config.chains[r.to].confirmations,'Reserved liquidity is no longer available');}
    const plan=T.funding(r.to,r.ownCoins,r.second,r.receive,r.fees.secondFunding,this.operator);
    r.ownFunding=T.signFunding(r.to,plan,r.ownCoins,this.key);r.ownFundingId=T.txid(r.to,r.ownFunding);
    r.ownRefund=T.signExit(r.to,T.exit(r.to,r.ownFundingId,r.second,r.receive,r.fees.secondExit,this.operator,true),r.second,r.receive,this.key);
    r.ownRefundId=T.txid(r.to,r.ownRefund);r.state='COUNTER_FUNDING';this.store.put(r);
  }
  async step(r){
    if(r.state==='EXPIRED')return;
    if(!r.userFunding){if(now()>r.expires){r.state='EXPIRED';this.store.transaction(()=>{this.store.put(r);this.store.release(r.id);});}return;}
    const a=this.chains[r.from],b=this.chains[r.to],ca=this.config.chains[r.from],cb=this.config.chains[r.to];
    const [first,tipA,tipB]=await Promise.all([a.status(r.userFundingId),a.tip(),b.tip()]);
    r.firstConfirmations=first.confirmations;
    if(!first.known&&!r.userRefundBroadcast&&tipA.mtp<r.first.time-this.config.claimSafetySeconds)await a.broadcast(r.userFunding);
    if(!r.ownFunding&&first.confirmations>=ca.confirmations&&tipB.mtp<r.second.time-this.config.counterFundingSafetySeconds&&this.config.enabled){
      const out=await a.outpoint(r.userFundingId,r.from==='tru'?1:0);T.check(out&&out.script===T.locking(r.from,r.first)&&out.amount===r.amount,'First HTLC is unavailable');await this.prepareCounter(r);
    }
    let second={known:false,confirmations:0};
    if(r.ownFunding){second=await b.status(r.ownFundingId);r.secondConfirmations=second.confirmations;
      if(!second.known&&first.confirmations>=ca.confirmations&&tipB.mtp<r.second.time-this.config.counterFundingSafetySeconds){await b.broadcast(r.ownFunding);r.state='COUNTER_FUNDING';}
      if(second.confirmations>=cb.confirmations&&first.confirmations>=ca.confirmations&&!r.userClaim)r.state='READY_TO_CLAIM';
      // Discover claims made outside this website using recovery tools.
      if(!r.userClaim&&second.confirmations>0){const out=await b.outpoint(r.ownFundingId,r.to==='tru'?1:0);if(!out){const spend=await b.findSpend(r.ownFundingId,r.to==='tru'?1:0,T.locking(r.to,r.second),r.secondHeight);if(spend&&T.extractSecret(spend.raw,r.to,r.hash)){r.userClaim=spend.raw;r.userClaimId=spend.id;}}}
    }
    if(r.userClaim){const secret=T.extractSecret(r.userClaim,r.to,r.hash);T.check(secret,'Claim secret missing');
      // Once a secret is public, persist and pursue the first-chain claim even
      // across reorgs. Never roll the record back into a fresh funding action.
      if(!r.ownClaim){r.ownClaim=T.signExit(r.from,T.exit(r.from,r.userFundingId,r.first,r.amount,r.fees.firstExit,this.operator),r.first,r.amount,this.key,secret);r.ownClaimId=T.txid(r.from,r.ownClaim);this.store.put(r);}
      const userClaim=await b.status(r.userClaimId);if(!userClaim.known&&second.known&&tipB.mtp<r.second.time)await b.broadcast(r.userClaim);
      if(await a.outpoint(r.userFundingId,r.from==='tru'?1:0))await a.broadcast(r.ownClaim);
      const ownClaim=await a.status(r.ownClaimId);r.claimConfirmations={user:userClaim.confirmations,operator:ownClaim.confirmations};
      r.state=userClaim.confirmations>=cb.confirmations&&ownClaim.confirmations>=ca.confirmations?'COMPLETE':'CLAIMING';if(r.state==='COMPLETE'&&!r.settledAt)r.settledAt=now();
    }
    if(!r.userClaim&&tipB.mtp>r.second.time&&r.ownFunding&&await b.outpoint(r.ownFundingId,r.to==='tru'?1:0)){await b.broadcast(r.ownRefund);r.ownRefundBroadcast=true;r.state='REFUNDING';}
    if(tipA.mtp>r.first.time&&await a.outpoint(r.userFundingId,r.from==='tru'?1:0)){await a.broadcast(r.userRefund);r.userRefundBroadcast=true;r.state='REFUNDING';}
    if(r.userRefundBroadcast||r.ownRefundBroadcast){const f=await a.status(r.userRefundId),s=r.ownRefundId?await b.status(r.ownRefundId):{confirmations:cb.confirmations};r.refundConfirmations={user:f.confirmations,operator:s.confirmations};if(f.confirmations>=ca.confirmations&&s.confirmations>=cb.confirmations)r.state='REFUNDED';}
    if(!terminal.has(r.state)&&first.confirmations<ca.confirmations&&r.ownFunding)r.notice='Funding confirmations changed; new actions are paused while the chain settles.';else delete r.notice;
    delete r.error;r.updated=now();this.store.put(r);
    // Terminal records keep their input reservations. On a reorg the same
    // signed transactions are recovered; inputs cannot enter a second swap.
  }
  async tick(){for(const r of this.store.all()){try{await this.step(r);}catch(e){r.error=String(e.message).slice(0,200);r.updated=now();this.store.put(r);}}}
  async withdraw(user,b){
    T.check(['tru','bsv','bsty'].includes(b.chain),'Unsupported chain');const chain=this.chains[b.chain],tx=T.parse(b.chain,b.raw),coins=[];
    T.check(tx.version===1&&tx.locktime===0&&tx.outputs.length===1&&/^76a914[0-9a-f]{40}88ac$/.test(tx.outputs[0].script),'Withdrawal must pay one standard address');
    for(const i of tx.inputs){const u=await chain.outpoint(i.txid,i.vout);T.check(u&&u.script===T.p2pkh(user)&&u.confirmations>=this.config.chains[b.chain].confirmations&&!this.store.reserved(b.chain,u),'Withdrawal input is missing or reserved');coins.push(u);}
    const fee=coins.reduce((s,u)=>s+T.atoms(u.amount),0n)-T.atoms(tx.outputs[0].amount);T.check(fee===T.atoms(this.config.chains[b.chain].fundingFee),'Unexpected withdrawal fee');T.verifyFunding(b.chain,b.raw,tx,coins,user);return {txid:await chain.broadcast(b.raw)};
  }
  view(r){const out={...r};delete out.ownRefund;delete out.ownClaim;return out;}
}
module.exports={Coordinator,select};

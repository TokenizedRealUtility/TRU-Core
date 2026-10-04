'use strict';
const T=require('./transactions');
function decimal(n,d,places=12){const scale=10n**BigInt(places),v=n*scale/d;return (v/scale).toString()+'.'+(v%scale).toString().padStart(places,'0');}
function marketData(store,now=Math.floor(Date.now()/1000)){
  const records=store.all().filter(r=>r.state==='COMPLETE'&&!r.error&&r.updated>=now-120&&r.settledAt);
  return {schema:'TRU-HOSTED-MARKETS-V1',market_type:'atomic_swap',scope:'this hosted service only',timestamp:now,price_convention:'quote coin units per 1 TRU; gross contract amounts, before exit fees',markets:['bsv','bsty'].map(quote=>{
    const trades=records.filter(r=>[r.from,r.to].includes(quote)).map(r=>({trade_id:r.id,pair:'TRU_'+quote.toUpperCase(),base:'TRU',quote:quote.toUpperCase(),base_atoms:r.from==='tru'?r.amount:r.receive,quote_atoms:r.from==='tru'?r.receive:r.amount,observed_settlement_time:r.settledAt,user_claim_txid:r.userClaimId,operator_claim_txid:r.ownClaimId,confirmations:r.claimConfirmations})).sort((a,b)=>a.observed_settlement_time-b.observed_settlement_time);
    const recent=trades.filter(t=>t.observed_settlement_time>=now-86400),last=trades.at(-1),base=recent.reduce((n,t)=>n+T.atoms(t.base_atoms),0n),q=recent.reduce((n,t)=>n+T.atoms(t.quote_atoms),0n);
    return {pair:'TRU_'+quote.toUpperCase(),base:'TRU',quote:quote.toUpperCase(),last_price:last?decimal(T.atoms(last.quote_atoms),T.atoms(last.base_atoms)):null,base_volume_24h:decimal(base,100000000n,8),quote_volume_24h:decimal(q,100000000n,8),trade_count_24h:recent.length,trades:recent,source:'both claim transactions confirmed on their respective chains',unconfirmed_quotes_included:false};
  })};
}
module.exports={marketData};

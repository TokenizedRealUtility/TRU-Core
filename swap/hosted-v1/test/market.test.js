const test=require('node:test'),assert=require('node:assert/strict'),{marketData}=require('../src/market-data');
test('Market feed excludes quotes, refunds, stale/error records and reorged settlement',()=>{
 const settled={state:'COMPLETE',updated:1000,settledAt:900,id:'settled',from:'tru',to:'bsv',amount:'100000000',receive:'200000000',userClaimId:'a',ownClaimId:'b',claimConfirmations:{user:6,operator:6}};
 const rows=[settled,...['QUOTED','CLAIMING','REFUNDED'].map(state=>({...settled,state})),{...settled,error:'node unavailable'},{...settled,updated:500}];
 const result=marketData({all:()=>rows},1000);assert.equal(result.markets[0].trade_count_24h,1);assert.equal(result.markets[0].last_price,'2.000000000000');assert.equal(result.markets[0].base_volume_24h,'1.00000000');assert.equal(result.markets[1].last_price,null);
});

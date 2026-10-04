'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),T=require('../src/transactions'),{Chain}=require('../src/chains'),{validateConfig}=require('../src/server');
async function main(){const file=process.argv[2]||'config.json',c=JSON.parse(fs.readFileSync(file));validateConfig(c);
 if(process.argv.includes('--init-key')){fs.mkdirSync(path.dirname(c.operatorKeyFile),{recursive:true,mode:0o700});fs.writeFileSync(c.operatorKeyFile,crypto.randomBytes(32).toString('hex')+'\n',{flag:'wx',mode:0o600});console.log('Created a NEW operator-only liquidity key. Back it up securely. No coins moved.');}
 let pub=null;if(fs.existsSync(c.operatorKeyFile))pub=T.pubkey(fs.readFileSync(c.operatorKeyFile,'utf8').trim());
 for(const [name,spec]of Object.entries(c.chains)){if(pub)console.log(name.toUpperCase()+' liquidity address: '+T.address(pub,spec.addressVersion));try{const chain=new Chain(name,spec),genesis=name==='tru'?(await chain.rpc('getblockbyheight',{height:1})).hash:await chain.rpc('getblockhash',[0]);console.log(name+' observed genesis: '+genesis);T.check(genesis===spec.genesis,'genesis does not match config');console.log(name+' tip: '+JSON.stringify(await chain.tip()));if(pub)console.log(name+' verified confirmed liquidity atoms: '+(await chain.coins(pub)).reduce((n,u)=>n+T.atoms(u.amount),0n));}catch(e){console.error(name+': '+e.message);process.exitCode=1;}}
 console.log('No funding, signing or broadcasts were performed by the connectivity checks.');}
main().catch(e=>{console.error(e.message);process.exitCode=1;});

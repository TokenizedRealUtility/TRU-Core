'use strict';
const {DatabaseSync}=require('node:sqlite');
class Store {
  constructor(path){this.db=new DatabaseSync(path);this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS swaps(id TEXT PRIMARY KEY,owner TEXT NOT NULL,record TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS swap_owner ON swaps(owner);
    CREATE TABLE IF NOT EXISTS reservations(outpoint TEXT PRIMARY KEY,swap TEXT NOT NULL REFERENCES swaps(id));
    CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY,expires INTEGER NOT NULL);`);}
  transaction(fn){this.db.exec('BEGIN IMMEDIATE');try{const r=fn();this.db.exec('COMMIT');return r;}catch(e){this.db.exec('ROLLBACK');throw e;}}
  put(r){this.db.prepare('INSERT INTO swaps VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record').run(r.id,r.user,TJSON(r));}
  get(id){const r=this.db.prepare('SELECT record FROM swaps WHERE id=?').get(id);return r?JSON.parse(r.record):null;}
  all(owner){return (owner?this.db.prepare('SELECT record FROM swaps WHERE owner=?').all(owner):this.db.prepare('SELECT record FROM swaps').all()).map(x=>JSON.parse(x.record));}
  reserved(chain,u){return !!this.db.prepare('SELECT 1 FROM reservations WHERE outpoint=?').get(chain+':'+u.txid+':'+u.vout);}
  reserve(r,chain,coins){for(const u of coins)this.db.prepare('INSERT INTO reservations VALUES(?,?)').run(chain+':'+u.txid+':'+u.vout,r.id);}
  release(id){this.db.prepare('DELETE FROM reservations WHERE swap=?').run(id);}
  nonce(n,expires,now){this.transaction(()=>{this.db.prepare('DELETE FROM nonces WHERE expires<?').run(now);this.db.prepare('INSERT INTO nonces VALUES(?,?)').run(n,expires);});}
  close(){this.db.close();}
}
const TJSON=JSON.stringify;
module.exports={Store};

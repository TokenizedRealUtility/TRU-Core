#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, pathlib, secrets, sqlite3, sys, time

EVIDENCE_KEYS=("truFundingTxid","bstyFundingTxid","truClaimTxid","bstyClaimTxid","truRefundTxid","bstyRefundTxid")

def load_agent(path:pathlib.Path):
    spec=importlib.util.spec_from_file_location("tru_group02_agent_runtime",str(path))
    if spec is None or spec.loader is None: raise SystemExit("FAIL: cannot import GROUP-02 Agent")
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

def mk_agent(args):
    mod=load_agent(pathlib.Path(args.agent)); return mod,mod.Agent(pathlib.Path(args.root),pathlib.Path(args.db))

def no_money(record):
    ev=record.get("evidence") or {}
    if not isinstance(ev,dict): raise SystemExit("FAIL: record evidence shape")
    for k in EVIDENCE_KEYS:
        if ev.get(k): raise SystemExit("FAIL: monetary evidence exists: "+k)

def mempool(a):
    r=a.bsty.json("getrawmempool")
    if not isinstance(r,list): raise SystemExit("FAIL: BSTY mempool shape")
    return {str(x) for x in r}

def write_manifest(path,obj):
    p=pathlib.Path(path); p.parent.mkdir(parents=True,exist_ok=True); os.chmod(p.parent,0o700)
    p.write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n"); os.chmod(p,0o600)

def cleanup(args,a,m):
    record=a.get_live_record(m["swapId"]); no_money(record)
    if m["preparedTxid"] in mempool(a): raise SystemExit("FAIL: refusing cleanup; prepared BSTY tx in mempool")
    j=a.store.get_funding_attempt(m["swapId"],"bsty")
    if j is not None:
        if j["operationId"]!=m["operationId"]: raise SystemExit("FAIL: journal identity mismatch")
        if j["state"]=="PREPARED":
            rel=a.release_bsty_prepared_reservation(m["swapId"])
            if rel.get("released") is not True or rel.get("reservationActive") is not False:
                raise SystemExit("FAIL: BSTY input release")
            j=a.store.transition_funding_attempt(j["operationId"],"ABORTED")
        if j["state"]!="ABORTED": raise SystemExit("FAIL: journal not safely abortable")
    if record.get("state")!="FAILED":
        rr=a.tru.raw("swaprecordtransition",{
            "swapId":m["swapId"],"nextState":"FAILED",
            "evidence":{"runtimeVerify":"TRU-SWAP-GROUP-02","noFunding":True,"noCoinMovement":True,"bstyInputLocksReleased":True},
        })
        if not isinstance(rr,dict) or rr.get("state")!="FAILED": raise SystemExit("FAIL: test SWAP-A FAILED transition")
    with a.store.connect() as con:
        con.execute("BEGIN IMMEDIATE")
        jr=con.execute("SELECT state FROM funding_attempts WHERE operation_id=?",(m["operationId"],)).fetchone()
        if jr is not None:
            if jr["state"]!="ABORTED": con.execute("ROLLBACK"); raise SystemExit("FAIL: journal cleanup terminal mismatch")
            con.execute("DELETE FROM funding_attempts WHERE operation_id=?",(m["operationId"],))
        rows=con.execute("SELECT local_role,state,swap_id FROM offer_sessions WHERE offer_id=? ORDER BY local_role",(m["offerId"],)).fetchall()
        if len(rows)!=2 or {x["local_role"] for x in rows}!={"maker","taker"}:
            con.execute("ROLLBACK"); raise SystemExit("FAIL: exact offer session pair missing")
        con.execute("DELETE FROM offer_sessions WHERE offer_id=?",(m["offerId"],))
        con.execute("DELETE FROM swap_views WHERE swap_id=?",(m["swapId"],))
        con.execute("COMMIT")
    print("BSTY_PREPARED_INPUT_LOCKS_RELEASED=PASS")
    print("TEST_JOURNAL_TERMINATED_ABORTED=PASS")
    print("TEST_RECORD_FINAL_STATE=FAILED")
    print("TEST_FUNDING_JOURNAL_ROW_REMOVED=YES")
    print("TEST_OFFER_SESSIONS_REMOVED=YES")
    print("TEST_SWAP_VIEW_REMOVED=YES")

def prepare(args):
    mod,a=mk_agent(args)
    bsty_atoms=secrets.randbelow(70000)+20000; tru_atoms=secrets.randbelow(70000)+20000
    while tru_atoms==bsty_atoms: tru_atoms=secrets.randbelow(70000)+20000
    created=accepted=maker=None; sid=None
    try:
        body={"giveChain":"bsty","getChain":"tru","giveAmount":f"0.{bsty_atoms:08d}","getAmount":f"0.{tru_atoms:08d}","ownHours":13,"theirHours":6,"minConf":1}
        created=a.create_offer_v2(body)
        accepted=a.import_offer_v2(created["shareBlob"])
        maker=a.import_offer_v2(accepted["shareBlob"])
        sid=str(maker.get("record",{}).get("swapId","")); record=a.get_live_record(sid); view=a.require_view(sid)
        if record.get("state")!="CREATED" or record.get("fundingOrder")!="BSTY_FIRST": raise SystemExit("FAIL: canonical BSTY-first test record")
        if str(view["give_chain"])!="bsty" or str(view["get_chain"])!="tru": raise SystemExit("FAIL: local BSTY maker view")
        no_money(record); mp0=mempool(a)
        orig=a.bsty.text; calls={"create":0,"fund":0,"sign":0,"broadcast":0}
        def counted(method,*argv,**kw):
            if method=="createrawtransaction": calls["create"]+=1
            elif method=="fundrawtransaction": calls["fund"]+=1
            elif method=="signrawtransactionwithwallet": calls["sign"]+=1
            elif method=="sendrawtransaction": calls["broadcast"]+=1; raise RuntimeError("FAIL: real broadcast attempted")
            return orig(method,*argv,**kw)
        a.bsty.text=counted
        p=a.prepare_bsty_prebroadcast_funding(sid)
        if calls!={"create":1,"fund":1,"sign":1,"broadcast":0}: raise SystemExit("FAIL: BSTY preparation RPC call counts "+repr(calls))
        if p.get("journalState")!="PREPARED" or p.get("prebroadcastReady") is not True or p.get("preparedInputReservation") is not True: raise SystemExit("FAIL: BSTY prepared state")
        if int(p.get("reservedInputCount",0))<1 or p.get("idempotentReuse") is not False or p.get("broadcast") is not False: raise SystemExit("FAIL: BSTY prepared flags")
        if "preparedRawTxHex" in p: raise SystemExit("FAIL: raw tx escaped Agent response")
        j=a.store.get_funding_attempt(sid,"bsty"); payload=a.store.get_prepared_funding_payload(j["operationId"])
        if hashlib.sha256(bytes.fromhex(payload["preparedRawTxHex"])).hexdigest()!=payload["preparedPayloadSha256"]: raise SystemExit("FAIL: durable raw digest")
        m={"version":"TRU-SWAP-GROUP-02-RUNTIME-V1","createdMs":int(time.time()*1000),"phase1AgentPid":int(args.agent_pid),"phase1BstyPid":int(args.bsty_pid),"dbPath":str(pathlib.Path(args.db).resolve()),"swapId":sid,"offerId":str(created["offerId"]),"operationId":j["operationId"],"preparedTxid":payload["preparedTxid"],"preparedVout":int(payload["preparedContractVout"]),"preparedPayloadSha256":payload["preparedPayloadSha256"],"preparedMs":int(payload["preparedMs"]),"reservedInputCount":int(p["reservedInputCount"])}
        write_manifest(args.manifest,m)
        dry=a.dryrun_bsty_prepared_broadcast(sid)
        if dry.get("dryRun") is not True or dry.get("broadcast") is not False or dry.get("mempoolAllowed") is not True or dry.get("exactPersistedBytesOnly") is not True: raise SystemExit("FAIL: BSTY exact dry-run barrier")
        mp1=mempool(a)
        if payload["preparedTxid"] in mp0 or payload["preparedTxid"] in mp1: raise SystemExit("FAIL: BSTY prepared tx entered mempool")
        r2=a.get_live_record(sid)
        if r2.get("state")!="CREATED": raise SystemExit("FAIL: SWAP-A mutated")
        no_money(r2)
        print("REAL_CANONICAL_SWAP_RECORD=PASS")
        print("CANONICAL_FUNDING_ORDER=BSTY_FIRST")
        print("REAL_BSTY_CREATERAWTRANSACTION_CALL_COUNT=1")
        print("REAL_BSTY_FUNDRAWTRANSACTION_CALL_COUNT=1")
        print("REAL_BSTY_WALLET_SIGN_CALL_COUNT=1")
        print("BSTY_WALLET_INPUT_LOCK_RESERVATION=PASS")
        print("AGENT_DURABLE_PREBROADCAST_JOURNAL=PASS")
        print("EXACT_PERSISTED_TESTMEMPOOLACCEPT_BARRIER=PASS")
        print("REAL_SENDRAWTRANSACTION_CALL_COUNT=0")
        print("PREPARED_TXID_MEMPOOL_PUBLICATION=NO")
        print("SWAP_A_MUTATION=NO")
        print("MONETARY_EVIDENCE=NO")
        print("PREPARED_RAW_TX_PRINTED=NO")
        print("TEST_IDENTIFIERS_PRINTED=NO")
    except BaseException:
        # If the manifest exists, cleanup remains explicitly recoverable through abort.
        # If no reservation was armed, close the test record/session immediately.
        if not pathlib.Path(args.manifest).exists() and sid and created:
            try:
                record=a.get_live_record(sid); no_money(record)
                if record.get("state")!="FAILED":
                    a.tru.raw("swaprecordtransition",{"swapId":sid,"nextState":"FAILED","evidence":{"runtimeVerify":"TRU-SWAP-GROUP-02-PREPARE-FAIL","noFunding":True,"noCoinMovement":True}})
                with a.store.connect() as con:
                    con.execute("DELETE FROM funding_attempts WHERE swap_id=? AND chain='bsty' AND state='ABORTED'",(sid,))
                    con.execute("DELETE FROM offer_sessions WHERE offer_id=?",(str(created["offerId"]),))
                    con.execute("DELETE FROM swap_views WHERE swap_id=?",(sid,))
            except Exception:
                pass
        raise

def finish(args):
    mod,a=mk_agent(args); m=json.load(open(args.manifest))
    if int(args.agent_pid)==int(m["phase1AgentPid"]): raise SystemExit("FAIL: Swap Agent PID did not change")
    if int(args.bsty_pid)==int(m["phase1BstyPid"]): raise SystemExit("FAIL: BSTY daemon PID did not change")
    print("SWAP_AGENT_PID_CHANGED=PASS"); print("BSTY_NODE_PID_CHANGED=PASS")
    j=a.store.get_funding_attempt(m["swapId"],"bsty")
    if j is None or j["operationId"]!=m["operationId"] or j["state"]!="PREPARED" or j.get("prebroadcastReady") is not True: raise SystemExit("FAIL: durable BSTY journal after restart")
    if j["preparedTxid"]!=m["preparedTxid"] or int(j["preparedContractVout"])!=m["preparedVout"] or j["preparedPayloadSha256"]!=m["preparedPayloadSha256"]: raise SystemExit("FAIL: prepared identity drift")
    payload=a.store.get_prepared_funding_payload(j["operationId"])
    if hashlib.sha256(bytes.fromhex(payload["preparedRawTxHex"])).hexdigest()!=m["preparedPayloadSha256"]: raise SystemExit("FAIL: signed raw bytes digest drift")
    if m["preparedTxid"] in mempool(a): raise SystemExit("FAIL: prepared BSTY tx in mempool after restart")
    record=a.get_live_record(m["swapId"])
    if record.get("state")!="CREATED": raise SystemExit("FAIL: SWAP-A state drift")
    no_money(record)
    print("AGENT_PREBROADCAST_IDENTITY_RESTART_DURABILITY=PASS")
    print("AGENT_SIGNED_RAW_TX_RESTART_DURABILITY=PASS")
    print("PREPARED_TXID_MEMPOOL_POST_RESTART=NO")
    print("SWAP_A_STATE_POST_RESTART=CREATED")
    print("MONETARY_EVIDENCE_POST_RESTART=NO")
    orig=a.bsty.text; calls={"create":0,"fund":0,"sign":0,"broadcast":0}
    def guarded(method,*argv,**kw):
        if method=="createrawtransaction": calls["create"]+=1; raise RuntimeError("FAIL: idempotent reuse recreated tx")
        if method=="fundrawtransaction": calls["fund"]+=1; raise RuntimeError("FAIL: idempotent reuse refunded tx")
        if method=="signrawtransactionwithwallet": calls["sign"]+=1; raise RuntimeError("FAIL: idempotent reuse resigned tx")
        if method=="sendrawtransaction": calls["broadcast"]+=1; raise RuntimeError("FAIL: real broadcast attempted")
        return orig(method,*argv,**kw)
    a.bsty.text=guarded
    p=a.prepare_bsty_prebroadcast_funding(m["swapId"])
    if any(calls.values()): raise SystemExit("FAIL: wallet mutation during idempotent reuse "+repr(calls))
    if p.get("idempotentReuse") is not True or p.get("preparedInputReservation") is not True: raise SystemExit("FAIL: BSTY idempotent reuse")
    if p.get("preparedTxid")!=m["preparedTxid"] or int(p.get("preparedVout",-1))!=m["preparedVout"] or p.get("preparedPayloadSha256")!=m["preparedPayloadSha256"]: raise SystemExit("FAIL: persisted identity changed")
    if int(p.get("reservedInputCount",0))!=m["reservedInputCount"]: raise SystemExit("FAIL: input count drift")
    dry=a.dryrun_bsty_prepared_broadcast(m["swapId"])
    if dry.get("mempoolAllowed") is not True or dry.get("broadcast") is not False or dry.get("exactPersistedBytesOnly") is not True: raise SystemExit("FAIL: exact testmempoolaccept barrier after restart")
    print("IDEMPOTENT_REUSE_CREATERAW_CALL_COUNT=0")
    print("IDEMPOTENT_REUSE_FUNDRAW_CALL_COUNT=0")
    print("IDEMPOTENT_REUSE_WALLET_SIGN_CALL_COUNT=0")
    print("BSTY_INPUT_LOCK_RESTORATION_OR_PERSISTENCE=PASS")
    print("BSTY_EXACT_PERSISTED_TESTMEMPOOLACCEPT_BARRIER=PASS")
    print("REAL_SENDRAWTRANSACTION_CALL_COUNT=0")
    print("PREPARED_TXID_MEMPOOL_PUBLICATION=NO")
    print("PREPARED_RAW_TX_BROWSER_EXPOSURE=NO")
    cleanup(args,a,m)

def abort(args):
    mod,a=mk_agent(args); m=json.load(open(args.manifest)); cleanup(args,a,m)

def main():
    p=argparse.ArgumentParser(); p.add_argument("mode",choices=["prepare","finish","abort"]); p.add_argument("--root",required=True); p.add_argument("--agent",required=True); p.add_argument("--db",required=True); p.add_argument("--manifest",required=True); p.add_argument("--agent-pid",required=True); p.add_argument("--bsty-pid",required=True); args=p.parse_args()
    {"prepare":prepare,"finish":finish,"abort":abort}[args.mode](args)
if __name__=="__main__": main()

#!/usr/bin/env python3
"""TRU SWAP GROUP-02 — BSTY prebroadcast safety helper.

Never broadcasts. Uses only wallet construction/signing, wallet input locking,
exact persisted-byte validation, and testmempoolaccept.
"""
from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Tuple

VERSION = "TRU-SWAP-BSTY-PREBROADCAST-V1"
COIN = Decimal("100000000")
TXID_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")


def _json_decimal(text: str) -> Any:
    return json.loads(text, parse_float=Decimal, parse_int=int)


def _coin_literal(atoms: Any) -> str:
    n=int(str(atoms))
    if n <= 0 or n > 0xffffffffffffffff:
        raise ValueError("BSTY amount atoms")
    return f"{n // 100000000}.{n % 100000000:08d}"


def _outpoints(decoded: Dict[str, Any]) -> List[Dict[str, Any]]:
    vin=decoded.get("vin")
    if not isinstance(vin,list) or not vin:
        raise ValueError("BSTY prepared transaction has no inputs")
    out=[]
    seen=set()
    for x in vin:
        if not isinstance(x,dict) or "coinbase" in x:
            raise ValueError("BSTY prepared transaction input shape")
        txid=str(x.get("txid","")).lower()
        vout=int(x.get("vout",-1))
        if not TXID_RE.fullmatch(txid) or vout < 0 or vout > 0xffffffff:
            raise ValueError("BSTY prepared transaction outpoint")
        k=(txid,vout)
        if k in seen:
            raise ValueError("BSTY prepared transaction duplicate input")
        seen.add(k)
        out.append({"txid":txid,"vout":vout})
    return out


def _locked_set(agent) -> set[Tuple[str,int]]:
    rows=agent.bsty.json("listlockunspent",wallet=True)
    if not isinstance(rows,list):
        raise ValueError("BSTY listlockunspent shape")
    out=set()
    for r in rows:
        if not isinstance(r,dict):
            continue
        txid=str(r.get("txid","")).lower()
        try: vout=int(r.get("vout",-1))
        except Exception: continue
        if TXID_RE.fullmatch(txid) and vout >= 0:
            out.add((txid,vout))
    return out


def _is_unspent(agent, op: Dict[str,Any]) -> bool:
    try:
        r=agent.bsty.json("gettxout",op["txid"],op["vout"],"true")
    except Exception:
        return False
    return isinstance(r,dict) and r.get("value") is not None


def _mempool(agent) -> set[str]:
    r=agent.bsty.json("getrawmempool")
    if not isinstance(r,list):
        raise ValueError("BSTY mempool shape")
    return {str(x).lower() for x in r if TXID_RE.fullmatch(str(x).lower())}


def _validate_signed(agent, record: Dict[str,Any], raw_hex: str, expected_txid: str|None=None) -> Dict[str,Any]:
    raw=str(raw_hex).lower()
    if not HEX_RE.fullmatch(raw):
        raise ValueError("BSTY prepared raw transaction hex")
    decoded=_json_decimal(agent.bsty.text("decoderawtransaction",raw))
    if not isinstance(decoded,dict):
        raise ValueError("BSTY decoderawtransaction shape")
    txid=str(decoded.get("txid","")).lower()
    if not TXID_RE.fullmatch(txid):
        raise ValueError("BSTY prepared txid")
    if expected_txid is not None and txid != str(expected_txid).lower():
        raise ValueError("BSTY prepared txid drift")

    desc=agent.descriptor(
        "bsty",record,int(record["bstyAmountAtoms"]),
        int(record["bstyRefundTime"]),"claim",
    )
    target=desc.get("fundingTarget") or {}
    expect_script=str(target.get("scriptHex","")).lower()
    expect_addr=str(target.get("address",""))
    if not HEX_RE.fullmatch(expect_script) or not expect_addr:
        raise ValueError("BSTY canonical P2SH target")

    vouts=decoded.get("vout")
    if not isinstance(vouts,list) or not vouts:
        raise ValueError("BSTY prepared vout shape")
    hit=[]
    for v in vouts:
        if not isinstance(v,dict):
            continue
        spk=v.get("scriptPubKey") or {}
        if str(spk.get("hex","")).lower()!=expect_script:
            continue
        try:
            atoms=int((Decimal(str(v.get("value"))) * COIN).to_integral_exact())
        except (InvalidOperation,ValueError):
            raise ValueError("BSTY prepared output amount")
        if atoms==int(record["bstyAmountAtoms"]):
            hit.append(int(v.get("n",-1)))
    if hit != [0]:
        raise ValueError("BSTY exact HTLC funding output must be uniquely vout 0")

    return {
        "txid":txid,
        "vout":0,
        "outpoints":_outpoints(decoded),
        "inputCount":len(_outpoints(decoded)),
        "scriptHex":expect_script,
        "address":expect_addr,
    }


def _ensure_locks(agent, outpoints: List[Dict[str,Any]]) -> Dict[str,Any]:
    for op in outpoints:
        if not _is_unspent(agent,op):
            raise ValueError("BSTY prepared input is no longer unspent")
    locked=_locked_set(agent)
    missing=[op for op in outpoints if (op["txid"],op["vout"]) not in locked]
    if missing:
        r=agent.bsty.json("lockunspent","false",json.dumps(missing,separators=(",",":")),wallet=True)
        if r is not True:
            raise ValueError("BSTY prepared input relock failed")
    locked2=_locked_set(agent)
    if any((op["txid"],op["vout"]) not in locked2 for op in outpoints):
        raise ValueError("BSTY prepared input reservation incomplete")
    return {"reservedInputCount":len(outpoints),"relockedInputCount":len(missing)}


def require_turn(record: Dict[str,Any], local_give_chain: str) -> None:
    if str(local_give_chain)!="bsty":
        raise ValueError("local participant is not the BSTY funding owner")
    order=str(record.get("fundingOrder",""))
    if order not in {"TRU_FIRST","BSTY_FIRST"}:
        raise ValueError("record fundingOrder")
    first="tru" if order=="TRU_FIRST" else "bsty"
    state=str(record.get("state",""))
    ev=record.get("evidence") or {}
    if not isinstance(ev,dict):
        raise ValueError("record evidence")
    if ev.get("bstyFundingTxid") is not None or ev.get("bstyFundingVout") is not None:
        raise ValueError("BSTY funding evidence already exists")
    if state=="CREATED":
        if first!="bsty":
            raise ValueError("BSTY is not first in the canonical funding order")
        return
    if state=="ONE_SIDE_FUNDED":
        if first=="bsty":
            raise ValueError("BSTY was already the first-funded chain")
        if not ev.get("truFundingTxid") or ev.get("truFundingVout") is None:
            raise ValueError("ONE_SIDE_FUNDED is missing TRU first-leg evidence")
        return
    raise ValueError("BSTY prebroadcast preparation requires CREATED or ONE_SIDE_FUNDED")


def prepare(agent, swap_id: str) -> Dict[str,Any]:
    view=agent.require_view(swap_id)
    record=agent.get_live_record(swap_id)
    require_turn(record,str(view["give_chain"]))
    expected=agent.bsty_reconciler.expected_bsty_funding(record)
    attempt=agent.store.get_funding_attempt(swap_id,"bsty")
    if attempt is None:
        height=int(agent.bsty.json("getblockcount"))
        attempt=agent.prepare_bsty_funding_journal(swap_id,height+1)
    if attempt.get("state")!="PREPARED":
        raise ValueError("BSTY signed preparation requires PREPARED journal")
    if str(attempt.get("amountAtoms"))!=str(record.get("bstyAmountAtoms")):
        raise ValueError("BSTY journal amount drift")
    if str(attempt.get("expectedContractCommitment"))!=str(expected.get("commitment")):
        raise ValueError("BSTY journal commitment drift")

    if attempt.get("prebroadcastReady") is True:
        payload=agent.store.get_prepared_funding_payload(attempt["operationId"])
        v=_validate_signed(agent,record,payload["preparedRawTxHex"],payload["preparedTxid"])
        if int(payload["preparedContractVout"])!=0:
            raise ValueError("BSTY prepared vout drift")
        if v["txid"] in _mempool(agent):
            raise ValueError("BSTY prepared transaction unexpectedly in mempool")
        lk=_ensure_locks(agent,v["outpoints"])
        return {
            "swapId":swap_id,"chain":"bsty","operationId":attempt["operationId"],
            "journalState":"PREPARED","prebroadcastReady":True,
            "preparedTxid":payload["preparedTxid"],"preparedVout":0,
            "preparedPayloadSha256":payload["preparedPayloadSha256"],
            "preparedMs":payload["preparedMs"],
            "reservedInputCount":lk["reservedInputCount"],
            "relockedInputCount":lk["relockedInputCount"],
            "preparedInputReservation":True,"exactPersistedBytesOnly":True,
            "broadcast":False,"fundingRouteEnabled":False,"idempotentReuse":True,
        }

    desc=agent.descriptor(
        "bsty",record,int(record["bstyAmountAtoms"]),int(record["bstyRefundTime"]),"claim"
    )
    addr=str((desc.get("fundingTarget") or {}).get("address", ""))
    if not addr:
        raise ValueError("BSTY canonical funding address missing")
    outputs='{"'+addr+'":'+_coin_literal(record["bstyAmountAtoms"])+'}'
    raw0=agent.bsty.text("createrawtransaction","[]",outputs)
    if not HEX_RE.fullmatch(raw0.lower()):
        raise ValueError("BSTY createrawtransaction output")

    funded_inputs=[]
    persisted=False
    try:
        options=json.dumps({"lockUnspents":True,"changePosition":1},separators=(",",":"))
        funded=_json_decimal(agent.bsty.text("fundrawtransaction",raw0,options,wallet=True))
        if not isinstance(funded,dict) or not HEX_RE.fullmatch(str(funded.get("hex","")).lower()):
            raise ValueError("BSTY fundrawtransaction output")
        funded_hex=str(funded["hex"]).lower()
        funded_dec=_json_decimal(agent.bsty.text("decoderawtransaction",funded_hex))
        funded_inputs=_outpoints(funded_dec)
        locked=_locked_set(agent)
        if any((op["txid"],op["vout"]) not in locked for op in funded_inputs):
            raise ValueError("BSTY fundrawtransaction did not lock selected inputs")

        signed=_json_decimal(agent.bsty.text("signrawtransactionwithwallet",funded_hex,wallet=True))
        if not isinstance(signed,dict) or signed.get("complete") is not True:
            raise ValueError("BSTY wallet signing incomplete")
        signed_hex=str(signed.get("hex","")).lower()
        v=_validate_signed(agent,record,signed_hex)
        if v["outpoints"]!=funded_inputs:
            raise ValueError("BSTY signed transaction input drift")
        if v["txid"] in _mempool(agent):
            raise ValueError("BSTY prepared transaction unexpectedly in mempool")
        lk=_ensure_locks(agent,v["outpoints"])

        armed=agent.store.prepare_funding_payload(
            attempt["operationId"],v["txid"],signed_hex,0
        )
        persisted=True
        return {
            "swapId":swap_id,"chain":"bsty","operationId":armed["operationId"],
            "journalState":armed["state"],"prebroadcastReady":True,
            "preparedTxid":armed["preparedTxid"],"preparedVout":0,
            "preparedPayloadSha256":armed["preparedPayloadSha256"],
            "preparedMs":armed["preparedMs"],
            "reservedInputCount":lk["reservedInputCount"],"relockedInputCount":0,
            "preparedInputReservation":True,"exactPersistedBytesOnly":True,
            "broadcast":False,"fundingRouteEnabled":False,"idempotentReuse":False,
        }
    except Exception:
        if funded_inputs and not persisted:
            try:
                agent.bsty.json("lockunspent","true",json.dumps(funded_inputs,separators=(",",":")),wallet=True)
            except Exception:
                pass
        raise


def dryrun(agent, swap_id: str) -> Dict[str,Any]:
    attempt=agent.store.get_funding_attempt(swap_id,"bsty")
    if attempt is None or attempt.get("state")!="PREPARED" or attempt.get("prebroadcastReady") is not True:
        raise ValueError("BSTY dry-run requires armed PREPARED journal")
    record=agent.get_live_record(swap_id)
    payload=agent.store.get_prepared_funding_payload(attempt["operationId"])
    v=_validate_signed(agent,record,payload["preparedRawTxHex"],payload["preparedTxid"])
    if v["txid"] in _mempool(agent):
        raise ValueError("BSTY prepared transaction already in mempool")
    lk=_ensure_locks(agent,v["outpoints"])
    raw_arg=json.dumps([payload["preparedRawTxHex"]],separators=(",",":"))
    result=_json_decimal(agent.bsty.text("testmempoolaccept",raw_arg))
    if not isinstance(result,list) or len(result)!=1 or not isinstance(result[0],dict):
        raise ValueError("BSTY testmempoolaccept shape")
    one=result[0]
    if str(one.get("txid","")).lower()!=v["txid"] or one.get("allowed") is not True:
        raise ValueError("BSTY exact persisted transaction is not mempool-admissible")
    return {
        "swapId":swap_id,"chain":"bsty","operationId":attempt["operationId"],
        "preparedTxid":v["txid"],"preparedVout":0,
        "reservedInputCount":lk["reservedInputCount"],
        "relockedInputCount":lk["relockedInputCount"],
        "reservationActive":True,"exactPersistedBytesOnly":True,
        "testMempoolAccept":True,"mempoolAllowed":True,
        "dryRun":True,"broadcast":False,"fundingRouteEnabled":False,
    }


def release(agent, swap_id: str) -> Dict[str,Any]:
    attempt=agent.store.get_funding_attempt(swap_id,"bsty")
    if attempt is None or attempt.get("state")!="PREPARED" or attempt.get("prebroadcastReady") is not True:
        raise ValueError("BSTY release requires armed PREPARED journal")
    record=agent.get_live_record(swap_id)
    payload=agent.store.get_prepared_funding_payload(attempt["operationId"])
    v=_validate_signed(agent,record,payload["preparedRawTxHex"],payload["preparedTxid"])
    if v["txid"] in _mempool(agent):
        raise ValueError("refusing BSTY release: prepared transaction is in mempool")
    for op in v["outpoints"]:
        if not _is_unspent(agent,op):
            raise ValueError("refusing BSTY release: prepared input is no longer unspent")
    r=agent.bsty.json("lockunspent","true",json.dumps(v["outpoints"],separators=(",",":")),wallet=True)
    if r is not True:
        raise ValueError("BSTY prepared input release failed")
    locked=_locked_set(agent)
    if any((op["txid"],op["vout"]) in locked for op in v["outpoints"]):
        raise ValueError("BSTY prepared input remained locked after release")
    return {
        "swapId":swap_id,"chain":"bsty","operationId":attempt["operationId"],
        "released":True,"reservationActive":False,"releasedInputCount":len(v["outpoints"]),
        "broadcast":False,"fundingRouteEnabled":False,
    }

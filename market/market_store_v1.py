#!/usr/bin/env python3
"""
TRU MARKET-MASTER-01 / MARKET-01C1 — durable public intent + handshake relay store.

Scope:
- durable public advert persistence
- atomic post/list/withdraw
- expiration materialization
- hashed owner-token cancellation capability
- active-pair enforcement through MARKET-01A.0 schema
- MARKET-01C0 durable reservation foundation
- MARKET-01C1 public take relay / fresh swap binding
- short-lived atomic HELD reservations
- durable V2 maker-offer / taker-accept / final handshake relay
- ACTION-STARTED-style finalization freeze before canonical record mutation
- exact maker/taker swapId equality before BOUND

No:
- wallet/RPC access
- private keys/preimages
- funding / claim / refund / broadcast
- custody of either participant wallet
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import secrets
import sqlite3
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

STORE_VERSION = "TRU-MARKET-STORE-01C1"
RESERVATION_VERSION = "TRU-MARKET-RESERVATION-01C1"
OWNER_TOKEN_BYTES = 32
ADVERT_ID_BYTES = 16
RESERVATION_TOKEN_BYTES = 32
RESERVATION_ID_BYTES = 16
DEFAULT_RESERVATION_SECONDS = 120
MIN_RESERVATION_SECONDS = 30
MAX_RESERVATION_SECONDS = 300
MAX_HANDSHAKE_BLOB_BYTES = 48 * 1024
OFFER_PREFIX_V2 = "TRUSWAP2:"
ACCEPT_PREFIX_V2 = "TRUSWAP2A:"
FINAL_PREFIX_V2 = "TRUSWAP2F:"
SECRET_RELAY_KEY_RE = re.compile(
    r"preimage|priv(?:ate)?key|private|wif|seed|mnemonic|passphrase|"
    r"auth(?:token)?|rpcpassword|walletpassword",
    re.IGNORECASE,
)

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "market_schema_v1.py"


def fail(message: str) -> None:
    raise RuntimeError(message)


def load_schema():
    if not SCHEMA_PATH.is_file():
        fail(f"missing schema module: {SCHEMA_PATH}")
    spec = importlib.util.spec_from_file_location("tru_market_schema_v1", SCHEMA_PATH)
    if spec is None or spec.loader is None:
        fail("could not load market schema module")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SCHEMA = load_schema()


def now_s() -> int:
    return int(time.time())


def token_hash(token: str) -> str:
    if not isinstance(token, str) or len(token) < 32:
        fail("invalid owner token")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def secure_token() -> str:
    return secrets.token_urlsafe(OWNER_TOKEN_BYTES)


def secure_advert_id() -> str:
    return secrets.token_hex(ADVERT_ID_BYTES)


def secure_reservation_token() -> str:
    return secrets.token_urlsafe(RESERVATION_TOKEN_BYTES)


def secure_reservation_id() -> str:
    return secrets.token_hex(RESERVATION_ID_BYTES)


def require_hex_id(name: str, value: str, chars: int) -> str:
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{chars}}}", value):
        fail(f"invalid {name}")
    return value


def _assert_no_secret_keys(obj: Any, path: str = "root") -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            k = str(key)
            if SECRET_RELAY_KEY_RE.search(k):
                # secretHash160 is a public commitment and is intentionally relayable.
                if k.lower().replace("_", "") not in {"secrethash160", "secrethash"}:
                    fail(f"handshake relay rejected secret-like key at {path}.{k}")
            _assert_no_secret_keys(value, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            _assert_no_secret_keys(value, f"{path}[{i}]")


def validate_handshake_blob(blob: Any, expected_prefix: str) -> str:
    if expected_prefix not in {OFFER_PREFIX_V2, ACCEPT_PREFIX_V2, FINAL_PREFIX_V2}:
        fail("internal handshake prefix policy error")
    text = str(blob or "").strip()
    if not text.startswith(expected_prefix):
        fail(f"handshake message must use {expected_prefix[:-1]}")
    if len(text.encode("utf-8")) > MAX_HANDSHAKE_BLOB_BYTES:
        fail("handshake message too large")
    payload = text[len(expected_prefix):]
    try:
        raw = base64.b64decode(payload, validate=True)
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("handshake message is damaged") from exc
    if not isinstance(obj, dict):
        fail("handshake message must contain a JSON object")
    _assert_no_secret_keys(obj)
    # Canonical relay identity is exact text bytes. Local Agents perform the
    # cryptographic/protocol validation; the market never becomes a key authority.
    return text


def db_connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except PermissionError:
        pass

    conn = sqlite3.connect(str(path), timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


DDL = """
CREATE TABLE IF NOT EXISTS market_meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS adverts (
    advert_id TEXT PRIMARY KEY,
    intent_hash TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    pair_id TEXT NOT NULL,
    side TEXT NOT NULL,
    base_atoms TEXT NOT NULL,
    quote_atoms TEXT NOT NULL,
    base_min_confirmations INTEGER NOT NULL,
    quote_min_confirmations INTEGER NOT NULL,
    funding_order TEXT NOT NULL,
    maker_refund_seconds INTEGER NOT NULL,
    taker_refund_seconds INTEGER NOT NULL,
    life_seconds INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('ACTIVE','WITHDRAWN','EXPIRED')),
    owner_token_hash TEXT NOT NULL,
    withdrawn_at INTEGER,
    CHECK(expires_at > created_at),
    CHECK(length(owner_token_hash) = 64)
);

CREATE INDEX IF NOT EXISTS idx_adverts_pair_status_created
    ON adverts(pair_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_adverts_expires
    ON adverts(status, expires_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_adverts_intent_active
    ON adverts(intent_hash)
    WHERE status='ACTIVE';

CREATE TABLE IF NOT EXISTS reservations (
    reservation_id TEXT PRIMARY KEY,
    advert_id TEXT NOT NULL REFERENCES adverts(advert_id) ON DELETE CASCADE,
    reservation_token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('HELD','RELEASED','EXPIRED','BOUND')),
    released_at INTEGER,
    bound_at INTEGER,
    swap_id TEXT,
    maker_offer_blob TEXT,
    taker_accept_blob TEXT,
    finalization_started_at INTEGER,
    maker_final_blob TEXT,
    maker_swap_id TEXT,
    taker_swap_id TEXT,
    updated_at INTEGER,
    CHECK(expires_at > created_at),
    CHECK(length(reservation_token_hash) = 64),
    CHECK(swap_id IS NULL OR length(swap_id) = 64),
    CHECK(maker_swap_id IS NULL OR length(maker_swap_id) = 64),
    CHECK(taker_swap_id IS NULL OR length(taker_swap_id) = 64)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_reservations_one_open_per_advert
    ON reservations(advert_id)
    WHERE status IN ('HELD','BOUND');

CREATE UNIQUE INDEX IF NOT EXISTS idx_reservations_bound_swap
    ON reservations(swap_id)
    WHERE swap_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_reservations_expiry
    ON reservations(status, expires_at);
"""


class MarketStore:
    def __init__(
        self,
        db_path: str | Path,
        *,
        reservation_write_enabled: bool = False,
    ):
        self.db_path = Path(db_path).expanduser()
        self.reservation_write_enabled = bool(reservation_write_enabled)
        self.conn = db_connect(self.db_path)
        self._init_db()

    def close(self) -> None:
        self.conn.close()

    def _init_db(self) -> None:
        self.conn.executescript(DDL)
        # MARKET-01C1 non-destructive migration for databases created by 01C0.
        existing = {r["name"] for r in self.conn.execute("PRAGMA table_info(reservations)").fetchall()}
        for name, decl in (
            ("maker_offer_blob", "TEXT"),
            ("taker_accept_blob", "TEXT"),
            ("finalization_started_at", "INTEGER"),
            ("maker_final_blob", "TEXT"),
            ("maker_swap_id", "TEXT"),
            ("taker_swap_id", "TEXT"),
            ("updated_at", "INTEGER"),
        ):
            if name not in existing:
                self.conn.execute(f"ALTER TABLE reservations ADD COLUMN {name} {decl}")
        self.conn.execute(
            "INSERT INTO market_meta(k,v) VALUES('storeVersion',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (STORE_VERSION,),
        )
        self.conn.execute(
            "INSERT INTO market_meta(k,v) VALUES('schemaVersion',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (SCHEMA.SCHEMA_VERSION,),
        )
        self.conn.execute(
            "INSERT INTO market_meta(k,v) VALUES('reservationVersion',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (RESERVATION_VERSION,),
        )
        try:
            os.chmod(self.db_path, 0o600)
        except (PermissionError, FileNotFoundError):
            pass

    def _expire_reservations_locked(self, ts: int) -> int:
        # Once finalization intent is durable, canonical record creation may have
        # happened even if a browser crashed before reporting the final bundle.
        # Never reopen that advert automatically. Reconciliation must finish it.
        cur = self.conn.execute(
            "UPDATE reservations SET status='EXPIRED', updated_at=? "
            "WHERE status='HELD' AND expires_at <= ? "
            "AND finalization_started_at IS NULL",
            (ts, ts),
        )
        return int(cur.rowcount)

    def _expire_locked(self, ts: int) -> int:
        self._expire_reservations_locked(ts)
        cur = self.conn.execute(
            "UPDATE adverts SET status='EXPIRED' "
            "WHERE status='ACTIVE' AND expires_at <= ? "
            "AND NOT EXISTS (SELECT 1 FROM reservations r "
            "WHERE r.advert_id=adverts.advert_id AND r.status IN ('HELD','BOUND'))",
            (ts,),
        )
        return int(cur.rowcount)

    def _require_reservation_writes(self) -> None:
        if not self.reservation_write_enabled:
            fail("reservation writes disabled until MARKET-01C activation")

    def _open_reservation_locked(self, advert_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM reservations WHERE advert_id=? "
            "AND status IN ('HELD','BOUND') ORDER BY created_at ASC LIMIT 1",
            (advert_id,),
        ).fetchone()

    @staticmethod
    def _reservation_public(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "reservationVersion": RESERVATION_VERSION,
            "reservationId": row["reservation_id"],
            "advertId": row["advert_id"],
            "createdAt": int(row["created_at"]),
            "expiresAt": int(row["expires_at"]),
            "status": row["status"],
            "swapId": row["swap_id"],
            "finalizationStarted": row["finalization_started_at"] is not None,
        }

    @staticmethod
    def _relay_view(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            **MarketStore._reservation_public(row),
            "makerOffer": row["maker_offer_blob"],
            "takerAcceptance": row["taker_accept_blob"],
            "finalizationStartedAt": row["finalization_started_at"],
            "makerFinal": row["maker_final_blob"],
            "makerSwapId": row["maker_swap_id"],
            "takerSwapId": row["taker_swap_id"],
            "updatedAt": row["updated_at"],
        }

    @staticmethod
    def _handoff_from_rows(advert: sqlite3.Row, reservation: sqlite3.Row) -> Dict[str, Any]:
        side = advert["side"]
        if side == "SELL_BASE":
            maker_give_chain, maker_give_atoms = "tru", advert["base_atoms"]
            maker_get_chain, maker_get_atoms = "bsty", advert["quote_atoms"]
        elif side == "BUY_BASE":
            maker_give_chain, maker_give_atoms = "bsty", advert["quote_atoms"]
            maker_get_chain, maker_get_atoms = "tru", advert["base_atoms"]
        else:
            fail("unsupported advert side")
        return {
            "reservationVersion": RESERVATION_VERSION,
            "reservationId": reservation["reservation_id"],
            "advertId": advert["advert_id"],
            "intentHash": advert["intent_hash"],
            "pairId": advert["pair_id"],
            "side": side,
            "makerGiveChain": maker_give_chain,
            "makerGiveAtoms": maker_give_atoms,
            "makerGetChain": maker_get_chain,
            "makerGetAtoms": maker_get_atoms,
            "takerGiveChain": maker_get_chain,
            "takerGiveAtoms": maker_get_atoms,
            "takerGetChain": maker_give_chain,
            "takerGetAtoms": maker_give_atoms,
            "baseMinConfirmations": int(advert["base_min_confirmations"]),
            "quoteMinConfirmations": int(advert["quote_min_confirmations"]),
            "fundingOrder": advert["funding_order"],
            "makerRefundSeconds": int(advert["maker_refund_seconds"]),
            "takerRefundSeconds": int(advert["taker_refund_seconds"]),
            "reservationExpiresAt": int(reservation["expires_at"]),
            "freshSwapRequired": True,
            "preexistingSwapIdAllowed": False,
        }

    @staticmethod
    def _public_from_row(row: sqlite3.Row) -> Dict[str, Any]:
        obj = {
            "schemaVersion": row["schema_version"],
            "pairId": row["pair_id"],
            "side": row["side"],
            "baseAtoms": row["base_atoms"],
            "quoteAtoms": row["quote_atoms"],
            "baseMinConfirmations": int(row["base_min_confirmations"]),
            "quoteMinConfirmations": int(row["quote_min_confirmations"]),
            "fundingOrder": row["funding_order"],
            "makerRefundSeconds": int(row["maker_refund_seconds"]),
            "takerRefundSeconds": int(row["taker_refund_seconds"]),
            "lifeSeconds": int(row["life_seconds"]),
            "advertId": row["advert_id"],
            "intentHash": row["intent_hash"],
            "createdAt": int(row["created_at"]),
            "expiresAt": int(row["expires_at"]),
            "status": row["status"],
        }
        # Defense in depth: pass every outward advert through the 01A.0 validator.
        return SCHEMA.validate_public_advert(obj, require_active_pair=False)

    def post(self, client_intent: Dict[str, Any], *, ts: Optional[int] = None, owner_token=None, max_active=None) -> Dict[str, Any]:
        """
        Atomically create one public advert.

        Returns:
          {
            "advert": <public advert>,
            "ownerToken": <private cancellation capability>
          }

        The owner token is returned once to the caller and is never stored in plaintext.
        """
        clean = SCHEMA.validate_client_intent(client_intent, require_active_pair=True)
        created = int(now_s() if ts is None else ts)
        if created <= 0:
            fail("invalid creation time")
        expires = created + int(clean["lifeSeconds"])
        intent_hash = SCHEMA.intent_hash_hex(clean, require_active_pair=True)

        if owner_token is not None and not re.fullmatch(r"[0-9a-f]{64}", str(owner_token)):
            fail("invalid durable owner capability")
        owner_token = owner_token or secure_token()
        owner_hash = token_hash(owner_token)

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(created)
            old = self.conn.execute("SELECT * FROM adverts WHERE owner_token_hash=?", (owner_hash,)).fetchone()
            if old is not None:
                if old["intent_hash"] != intent_hash:
                    fail("durable post identity changed")
                public = self._public_from_row(old)
                self.conn.execute("COMMIT")
                return {"advert": public, "ownerToken": owner_token}

            if max_active is not None:
                count = self.conn.execute("SELECT COUNT(*) FROM adverts WHERE status='ACTIVE'").fetchone()[0]
                if count >= int(max_active):
                    fail("public intent book active-advert cap reached")
            # An identical still-active intent is rejected rather than silently
            # creating duplicate visible liquidity.
            row = self.conn.execute(
                "SELECT advert_id FROM adverts WHERE intent_hash=? AND status='ACTIVE'",
                (intent_hash,),
            ).fetchone()
            if row is not None:
                fail("identical active intent already exists")

            advert_id = None
            for _ in range(8):
                candidate = secure_advert_id()
                exists = self.conn.execute(
                    "SELECT 1 FROM adverts WHERE advert_id=?", (candidate,)
                ).fetchone()
                if exists is None:
                    advert_id = candidate
                    break
            if advert_id is None:
                fail("could not allocate unique advertId")

            self.conn.execute(
                """
                INSERT INTO adverts(
                    advert_id,intent_hash,schema_version,pair_id,side,
                    base_atoms,quote_atoms,
                    base_min_confirmations,quote_min_confirmations,
                    funding_order,maker_refund_seconds,taker_refund_seconds,
                    life_seconds,created_at,expires_at,status,owner_token_hash,withdrawn_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)
                """,
                (
                    advert_id, intent_hash, clean["schemaVersion"], clean["pairId"], clean["side"],
                    clean["baseAtoms"], clean["quoteAtoms"],
                    clean["baseMinConfirmations"], clean["quoteMinConfirmations"],
                    clean["fundingOrder"], clean["makerRefundSeconds"], clean["takerRefundSeconds"],
                    clean["lifeSeconds"], created, expires, "ACTIVE", owner_hash,
                ),
            )
            row = self.conn.execute(
                "SELECT * FROM adverts WHERE advert_id=?", (advert_id,)
            ).fetchone()
            if row is None:
                fail("post readback failed")
            public = self._public_from_row(row)
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

        return {"advert": public, "ownerToken": owner_token}

    def list_active(self, *, pair_id: Optional[str] = None, ts: Optional[int] = None) -> List[Dict[str, Any]]:
        current = int(now_s() if ts is None else ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            if pair_id is None:
                rows = self.conn.execute(
                    "SELECT a.* FROM adverts a WHERE a.status='ACTIVE' "
                    "AND NOT EXISTS (SELECT 1 FROM reservations r "
                    "WHERE r.advert_id=a.advert_id AND r.status IN ('HELD','BOUND')) "
                    "ORDER BY a.created_at DESC, a.advert_id ASC"
                ).fetchall()
            else:
                SCHEMA.pair_spec(pair_id, require_active=False)
                rows = self.conn.execute(
                    "SELECT a.* FROM adverts a WHERE a.status='ACTIVE' AND a.pair_id=? "
                    "AND NOT EXISTS (SELECT 1 FROM reservations r "
                    "WHERE r.advert_id=a.advert_id AND r.status IN ('HELD','BOUND')) "
                    "ORDER BY a.created_at DESC, a.advert_id ASC",
                    (pair_id,),
                ).fetchall()
            out = [self._public_from_row(r) for r in rows]
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def get_public(self, advert_id: str, *, ts: Optional[int] = None) -> Optional[Dict[str, Any]]:
        current = int(now_s() if ts is None else ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            row = self.conn.execute(
                "SELECT * FROM adverts WHERE advert_id=?", (advert_id,)
            ).fetchone()
            out = None if row is None else self._public_from_row(row)
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def reserve(
        self,
        advert_id: str,
        *,
        hold_seconds: int = DEFAULT_RESERVATION_SECONDS,
        ts: Optional[int] = None, reservation_token=None,
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        require_hex_id("advertId", advert_id, ADVERT_ID_BYTES * 2)
        hold = int(hold_seconds)
        if hold < MIN_RESERVATION_SECONDS or hold > MAX_RESERVATION_SECONDS:
            fail(
                f"reservation hold must be {MIN_RESERVATION_SECONDS}.."
                f"{MAX_RESERVATION_SECONDS} seconds"
            )
        current = int(now_s() if ts is None else ts)
        if reservation_token is not None and not re.fullmatch(r"[0-9a-f]{64}", str(reservation_token)):
            fail("invalid durable reservation capability")
        reservation_token = reservation_token or secure_reservation_token()
        reservation_hash = token_hash(reservation_token)

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            advert = self.conn.execute(
                "SELECT * FROM adverts WHERE advert_id=?", (advert_id,)
            ).fetchone()
            if advert is None:
                fail("advert not found")
            old = self.conn.execute("SELECT * FROM reservations WHERE reservation_token_hash=?", (reservation_hash,)).fetchone()
            if old is not None:
                if old["advert_id"] != advert_id:
                    fail("durable reservation identity changed")
                result = {"reservation": self._reservation_public(old), "reservationToken": reservation_token,
                          "handoff": self._handoff_from_rows(advert, old)}
                self.conn.execute("COMMIT")
                return result
            if advert["status"] != "ACTIVE":
                fail(f"advert is not active: {advert['status']}")
            if self._open_reservation_locked(advert_id) is not None:
                fail("advert already has an open reservation")

            reservation_expires = min(
                current + hold,
                int(advert["expires_at"]),
            )
            if reservation_expires <= current:
                fail("advert expires before a reservation can be held")

            reservation_id = None
            for _ in range(8):
                candidate = secure_reservation_id()
                exists = self.conn.execute(
                    "SELECT 1 FROM reservations WHERE reservation_id=?",
                    (candidate,),
                ).fetchone()
                if exists is None:
                    reservation_id = candidate
                    break
            if reservation_id is None:
                fail("could not allocate unique reservationId")

            self.conn.execute(
                "INSERT INTO reservations("
                "reservation_id,advert_id,reservation_token_hash,"
                "created_at,expires_at,status,released_at,bound_at,swap_id,updated_at"
                ") VALUES(?,?,?,?,?,'HELD',NULL,NULL,NULL,?)",
                (
                    reservation_id,
                    advert_id,
                    reservation_hash,
                    current,
                    reservation_expires,
                    current,
                ),
            )
            reservation = self.conn.execute(
                "SELECT * FROM reservations WHERE reservation_id=?",
                (reservation_id,),
            ).fetchone()
            if reservation is None:
                fail("reservation readback failed")
            public = self._reservation_public(reservation)
            handoff = self._handoff_from_rows(advert, reservation)
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

        return {
            "reservation": public,
            "reservationToken": reservation_token,
            "handoff": handoff,
        }

    def reservation_handoff(
        self,
        reservation_id: str,
        reservation_token: str,
        *,
        ts: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        require_hex_id("reservationId", reservation_id, RESERVATION_ID_BYTES * 2)
        supplied_hash = token_hash(reservation_token)
        current = int(now_s() if ts is None else ts)

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            reservation = self.conn.execute(
                "SELECT * FROM reservations WHERE reservation_id=?",
                (reservation_id,),
            ).fetchone()
            if reservation is None:
                fail("reservation not found")
            if reservation["status"] != "HELD":
                fail(f"reservation is not held: {reservation['status']}")
            if not secrets.compare_digest(
                reservation["reservation_token_hash"], supplied_hash
            ):
                fail("reservation token rejected")
            advert = self.conn.execute(
                "SELECT * FROM adverts WHERE advert_id=?",
                (reservation["advert_id"],),
            ).fetchone()
            if advert is None or advert["status"] != "ACTIVE":
                fail("reserved advert is no longer active")
            out = self._handoff_from_rows(advert, reservation)
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def release_reservation(
        self,
        reservation_id: str,
        reservation_token: str,
        *,
        ts: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        require_hex_id("reservationId", reservation_id, RESERVATION_ID_BYTES * 2)
        supplied_hash = token_hash(reservation_token)
        current = int(now_s() if ts is None else ts)

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            reservation = self.conn.execute(
                "SELECT * FROM reservations WHERE reservation_id=?",
                (reservation_id,),
            ).fetchone()
            if reservation is None:
                fail("reservation not found")
            if reservation["status"] != "HELD":
                fail(f"reservation is not held: {reservation['status']}")
            if not secrets.compare_digest(
                reservation["reservation_token_hash"], supplied_hash
            ):
                fail("reservation token rejected")
            if reservation["finalization_started_at"] is not None:
                fail("reservation cannot be released after finalization started; canonical evidence reconciliation required")
            cur = self.conn.execute(
                "UPDATE reservations SET status='RELEASED', released_at=?, updated_at=? "
                "WHERE reservation_id=? AND status='HELD' AND finalization_started_at IS NULL",
                (current, current, reservation_id),
            )
            if cur.rowcount != 1:
                fail("reservation release lost atomicity race")
            row2 = self.conn.execute(
                "SELECT * FROM reservations WHERE reservation_id=?",
                (reservation_id,),
            ).fetchone()
            out = self._reservation_public(row2)
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def bind_reservation_to_fresh_swap(
        self,
        reservation_id: str,
        reservation_token: str,
        swap_id: str,
        *,
        ts: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        require_hex_id("reservationId", reservation_id, RESERVATION_ID_BYTES * 2)
        swap_id = require_hex_id("fresh swapId", swap_id, 64)
        supplied_hash = token_hash(reservation_token)
        current = int(now_s() if ts is None else ts)

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            reservation = self.conn.execute(
                "SELECT * FROM reservations WHERE reservation_id=?",
                (reservation_id,),
            ).fetchone()
            if reservation is None:
                fail("reservation not found")
            if reservation["status"] != "HELD":
                fail(f"reservation is not held: {reservation['status']}")
            if not secrets.compare_digest(
                reservation["reservation_token_hash"], supplied_hash
            ):
                fail("reservation token rejected")
            advert = self.conn.execute(
                "SELECT * FROM adverts WHERE advert_id=?",
                (reservation["advert_id"],),
            ).fetchone()
            if advert is None or advert["status"] != "ACTIVE":
                fail("reserved advert is no longer active")
            try:
                cur = self.conn.execute(
                    "UPDATE reservations SET status='BOUND', bound_at=?, swap_id=?, updated_at=? "
                    "WHERE reservation_id=? AND status='HELD'",
                    (current, swap_id, current, reservation_id),
                )
            except sqlite3.IntegrityError as exc:
                raise RuntimeError("swapId is already bound to another reservation") from exc
            if cur.rowcount != 1:
                fail("swap binding lost atomicity race")
            row2 = self.conn.execute(
                "SELECT * FROM reservations WHERE reservation_id=?",
                (reservation_id,),
            ).fetchone()
            out = self._reservation_public(row2)
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def _owner_reservation_locked(
        self, advert_id: str, owner_token: str, current: int
    ) -> tuple[sqlite3.Row, Optional[sqlite3.Row]]:
        require_hex_id("advertId", advert_id, ADVERT_ID_BYTES * 2)
        supplied_hash = token_hash(owner_token)
        self._expire_locked(current)
        advert = self.conn.execute(
            "SELECT * FROM adverts WHERE advert_id=?", (advert_id,)
        ).fetchone()
        if advert is None:
            fail("advert not found")
        if not secrets.compare_digest(advert["owner_token_hash"], supplied_hash):
            fail("owner token rejected")
        reservation = self._open_reservation_locked(advert_id)
        return advert, reservation

    def owner_reservation(
        self, advert_id: str, owner_token: str, *, ts: Optional[int] = None
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        current = int(now_s() if ts is None else ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            advert, reservation = self._owner_reservation_locked(advert_id, owner_token, current)
            if reservation is None:
                out = {"reservation": None, "handoff": None}
            else:
                out = {
                    "reservation": self._relay_view(reservation),
                    "handoff": self._handoff_from_rows(advert, reservation),
                }
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def reservation_status(
        self, reservation_id: str, reservation_token: str, *, ts: Optional[int] = None
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        require_hex_id("reservationId", reservation_id, RESERVATION_ID_BYTES * 2)
        supplied_hash = token_hash(reservation_token)
        current = int(now_s() if ts is None else ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            reservation = self.conn.execute(
                "SELECT * FROM reservations WHERE reservation_id=?", (reservation_id,)
            ).fetchone()
            if reservation is None:
                fail("reservation not found")
            if not secrets.compare_digest(reservation["reservation_token_hash"], supplied_hash):
                fail("reservation token rejected")
            advert = self.conn.execute(
                "SELECT * FROM adverts WHERE advert_id=?", (reservation["advert_id"],)
            ).fetchone()
            if advert is None:
                fail("reserved advert missing")
            out = {
                "reservation": self._relay_view(reservation),
                "handoff": self._handoff_from_rows(advert, reservation),
            }
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def submit_maker_offer(
        self, advert_id: str, owner_token: str, reservation_id: str, offer_blob: Any,
        *, ts: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        require_hex_id("reservationId", reservation_id, RESERVATION_ID_BYTES * 2)
        offer = validate_handshake_blob(offer_blob, OFFER_PREFIX_V2)
        current = int(now_s() if ts is None else ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            _, reservation = self._owner_reservation_locked(advert_id, owner_token, current)
            if reservation is None or reservation["reservation_id"] != reservation_id:
                fail("reservation is not the advert's open reservation")
            if reservation["status"] != "HELD":
                fail(f"reservation is not held: {reservation['status']}")
            old = reservation["maker_offer_blob"]
            if old is not None and old != offer:
                fail("different maker offer already bound to reservation")
            if reservation["taker_accept_blob"] is not None and old is None:
                fail("acceptance exists without maker offer; refusing inconsistent relay state")
            if old is None:
                self.conn.execute(
                    "UPDATE reservations SET maker_offer_blob=?, updated_at=? "
                    "WHERE reservation_id=? AND maker_offer_blob IS NULL",
                    (offer, current, reservation_id),
                )
            row = self.conn.execute("SELECT * FROM reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
            out = self._relay_view(row)
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def submit_taker_accept(
        self, reservation_id: str, reservation_token: str, acceptance_blob: Any,
        *, ts: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        require_hex_id("reservationId", reservation_id, RESERVATION_ID_BYTES * 2)
        supplied_hash = token_hash(reservation_token)
        acceptance = validate_handshake_blob(acceptance_blob, ACCEPT_PREFIX_V2)
        current = int(now_s() if ts is None else ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            row = self.conn.execute("SELECT * FROM reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
            if row is None:
                fail("reservation not found")
            if not secrets.compare_digest(row["reservation_token_hash"], supplied_hash):
                fail("reservation token rejected")
            if row["status"] != "HELD":
                fail(f"reservation is not held: {row['status']}")
            if row["maker_offer_blob"] is None:
                fail("maker offer is not available yet")
            old = row["taker_accept_blob"]
            if old is not None and old != acceptance:
                fail("different taker acceptance already bound to reservation")
            if row["finalization_started_at"] is not None and old is None:
                fail("finalization started without acceptance; refusing inconsistent relay state")
            if old is None:
                self.conn.execute(
                    "UPDATE reservations SET taker_accept_blob=?, updated_at=? "
                    "WHERE reservation_id=? AND taker_accept_blob IS NULL",
                    (acceptance, current, reservation_id),
                )
            row = self.conn.execute("SELECT * FROM reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
            out = self._relay_view(row)
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def mark_finalization_started(
        self, advert_id: str, owner_token: str, reservation_id: str,
        *, ts: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        require_hex_id("reservationId", reservation_id, RESERVATION_ID_BYTES * 2)
        current = int(now_s() if ts is None else ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            _, row = self._owner_reservation_locked(advert_id, owner_token, current)
            if row is None or row["reservation_id"] != reservation_id:
                fail("reservation is not the advert's open reservation")
            if row["status"] != "HELD":
                fail(f"reservation is not held: {row['status']}")
            if row["maker_offer_blob"] is None or row["taker_accept_blob"] is None:
                fail("maker offer and taker acceptance are required before finalization")
            if row["finalization_started_at"] is None:
                self.conn.execute(
                    "UPDATE reservations SET finalization_started_at=?, updated_at=? "
                    "WHERE reservation_id=? AND finalization_started_at IS NULL",
                    (current, current, reservation_id),
                )
            row = self.conn.execute("SELECT * FROM reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
            out = self._relay_view(row)
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def submit_maker_final(
        self, advert_id: str, owner_token: str, reservation_id: str,
        final_blob: Any, swap_id: str, *, ts: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        require_hex_id("reservationId", reservation_id, RESERVATION_ID_BYTES * 2)
        swap_id = require_hex_id("maker swapId", swap_id, 64)
        final = validate_handshake_blob(final_blob, FINAL_PREFIX_V2)
        current = int(now_s() if ts is None else ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            _, row = self._owner_reservation_locked(advert_id, owner_token, current)
            if row is None or row["reservation_id"] != reservation_id:
                fail("reservation is not the advert's open reservation")
            if row["status"] != "HELD":
                if row["status"] == "BOUND" and row["maker_final_blob"] == final and row["maker_swap_id"] == swap_id:
                    out = self._relay_view(row); self.conn.execute("COMMIT"); return out
                fail(f"reservation is not held: {row['status']}")
            if row["finalization_started_at"] is None:
                fail("finalization-start intent must be durable before canonical record result")
            if row["maker_offer_blob"] is None or row["taker_accept_blob"] is None:
                fail("handshake relay is incomplete")
            if row["maker_final_blob"] is not None and row["maker_final_blob"] != final:
                fail("different maker final already bound to reservation")
            if row["maker_swap_id"] is not None and row["maker_swap_id"] != swap_id:
                fail("different maker swapId already bound to reservation")
            self.conn.execute(
                "UPDATE reservations SET maker_final_blob=COALESCE(maker_final_blob,?), "
                "maker_swap_id=COALESCE(maker_swap_id,?), updated_at=? WHERE reservation_id=?",
                (final, swap_id, current, reservation_id),
            )
            row = self.conn.execute("SELECT * FROM reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
            out = self._relay_view(row)
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def acknowledge_taker_and_bind(
        self, reservation_id: str, reservation_token: str, swap_id: str,
        *, ts: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._require_reservation_writes()
        require_hex_id("reservationId", reservation_id, RESERVATION_ID_BYTES * 2)
        swap_id = require_hex_id("taker swapId", swap_id, 64)
        supplied_hash = token_hash(reservation_token)
        current = int(now_s() if ts is None else ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            row = self.conn.execute("SELECT * FROM reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
            if row is None:
                fail("reservation not found")
            if not secrets.compare_digest(row["reservation_token_hash"], supplied_hash):
                fail("reservation token rejected")
            if row["status"] == "BOUND":
                if row["swap_id"] == swap_id and row["maker_swap_id"] == swap_id and row["taker_swap_id"] == swap_id:
                    out = self._relay_view(row); self.conn.execute("COMMIT"); return out
                fail("bound reservation swapId mismatch")
            if row["status"] != "HELD":
                fail(f"reservation is not held: {row['status']}")
            if row["finalization_started_at"] is None or row["maker_final_blob"] is None:
                fail("maker finalization is not available yet")
            if row["maker_swap_id"] != swap_id:
                fail("maker/taker swapId mismatch")
            try:
                cur = self.conn.execute(
                    "UPDATE reservations SET status='BOUND', bound_at=?, swap_id=?, "
                    "taker_swap_id=?, updated_at=? WHERE reservation_id=? AND status='HELD'",
                    (current, swap_id, swap_id, current, reservation_id),
                )
            except sqlite3.IntegrityError as exc:
                raise RuntimeError("swapId is already bound to another reservation") from exc
            if cur.rowcount != 1:
                fail("taker binding lost atomicity race")
            row = self.conn.execute("SELECT * FROM reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
            out = self._relay_view(row)
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def withdraw(self, advert_id: str, owner_token: str, *, ts: Optional[int] = None) -> Dict[str, Any]:
        current = int(now_s() if ts is None else ts)
        supplied_hash = token_hash(owner_token)

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            row = self.conn.execute(
                "SELECT * FROM adverts WHERE advert_id=?", (advert_id,)
            ).fetchone()
            if row is None:
                fail("advert not found")
            if row["status"] != "ACTIVE":
                fail(f"advert is not active: {row['status']}")
            open_reservation = self._open_reservation_locked(advert_id)
            if open_reservation is not None:
                fail(
                    "advert cannot be withdrawn while reservation is "
                    f"{open_reservation['status']}"
                )
            if not secrets.compare_digest(row["owner_token_hash"], supplied_hash):
                fail("owner token rejected")

            cur = self.conn.execute(
                "UPDATE adverts SET status='WITHDRAWN', withdrawn_at=? "
                "WHERE advert_id=? AND status='ACTIVE'",
                (current, advert_id),
            )
            if cur.rowcount != 1:
                fail("withdraw lost atomicity race")

            row2 = self.conn.execute(
                "SELECT * FROM adverts WHERE advert_id=?", (advert_id,)
            ).fetchone()
            public = self._public_from_row(row2)
            self.conn.execute("COMMIT")
            return public
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def counts(self, *, ts: Optional[int] = None) -> Dict[str, int]:
        current = int(now_s() if ts is None else ts)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self._expire_locked(current)
            rows = self.conn.execute(
                "SELECT status, COUNT(*) AS n FROM adverts GROUP BY status"
            ).fetchall()
            out = {"ACTIVE": 0, "WITHDRAWN": 0, "EXPIRED": 0}
            for r in rows:
                out[str(r["status"])] = int(r["n"])
            reservation_rows = self.conn.execute(
                "SELECT status, COUNT(*) AS n FROM reservations GROUP BY status"
            ).fetchall()
            for status in ("HELD", "RELEASED", "EXPIRED", "BOUND"):
                out[f"RESERVATION_{status}"] = 0
            for r in reservation_rows:
                out[f"RESERVATION_{str(r['status'])}"] = int(r["n"])
            self.conn.execute("COMMIT")
            return out
        except Exception:
            self.conn.execute("ROLLBACK")
            raise


def sample_intent(**overrides) -> Dict[str, Any]:
    d = {
        "schemaVersion": SCHEMA.SCHEMA_VERSION,
        "pairId": "TRU_BSTY",
        "side": "SELL_BASE",
        "baseAtoms": "10000000000",
        "quoteAtoms": "1000000000000",
        "baseMinConfirmations": 6,
        "quoteMinConfirmations": 6,
        "fundingOrder": "MAKER_FIRST",
        "makerRefundSeconds": 86400,
        "takerRefundSeconds": 43200,
        "lifeSeconds": 21600,
    }
    d.update(overrides)
    return d


def selftest() -> None:
    with tempfile.TemporaryDirectory(prefix="tru-market-01a1-") as td:
        db = Path(td) / "market.sqlite3"
        s = MarketStore(db)
        t0 = 2_000_000_000

        created = s.post(sample_intent(), ts=t0)
        advert = created["advert"]
        owner = created["ownerToken"]

        assert len(owner) >= 32
        assert "ownerToken" not in advert
        assert advert["status"] == "ACTIVE"
        assert len(s.list_active(ts=t0 + 1)) == 1

        # Plaintext owner token must not be present in the DB file.
        raw = db.read_bytes()
        assert owner.encode() not in raw

        # Wrong capability cannot cancel.
        try:
            s.withdraw(advert["advertId"], secure_token(), ts=t0 + 2)
            raise AssertionError("wrong owner token withdrew advert")
        except RuntimeError as exc:
            assert "owner token rejected" in str(exc)

        assert s.get_public(advert["advertId"], ts=t0 + 3)["status"] == "ACTIVE"

        # Duplicate live liquidity is refused.
        try:
            s.post(sample_intent(), ts=t0 + 4)
            raise AssertionError("duplicate active intent accepted")
        except RuntimeError as exc:
            assert "identical active intent" in str(exc)

        withdrawn = s.withdraw(advert["advertId"], owner, ts=t0 + 5)
        assert withdrawn["status"] == "WITHDRAWN"
        assert s.list_active(ts=t0 + 6) == []

        # Reposting the same intent after withdrawal is allowed and gets a new ID.
        created2 = s.post(sample_intent(), ts=t0 + 7)
        assert created2["advert"]["advertId"] != advert["advertId"]

        # Expiration is durable/materialized on read.
        exp = s.post(sample_intent(
            side="BUY_BASE",
            baseAtoms="5000000000",
            quoteAtoms="450000000000",
            lifeSeconds=300,
        ), ts=t0 + 10)
        assert len(s.list_active(ts=t0 + 20)) == 2
        assert s.get_public(exp["advert"]["advertId"], ts=t0 + 311)["status"] == "EXPIRED"

        # Planned pair remains fail-closed through the store.
        try:
            s.post(sample_intent(pairId="TRU_BTC"), ts=t0 + 12)
            raise AssertionError("planned pair posted")
        except ValueError as exc:
            assert "not active" in str(exc)

        # Restart persistence.
        keep_id = created2["advert"]["advertId"]
        s.close()
        s2 = MarketStore(db)
        assert s2.get_public(keep_id, ts=t0 + 100)["status"] == "ACTIVE"

        # Public serialization cannot contain private capability/hash fields.
        public_blob = json.dumps(s2.list_active(ts=t0 + 100), sort_keys=True)
        assert "ownerToken" not in public_blob
        assert "owner_token_hash" not in public_blob
        assert owner not in public_blob

        counts = s2.counts(ts=t0 + 400)
        assert counts["WITHDRAWN"] == 1
        assert counts["EXPIRED"] == 1
        assert counts["ACTIVE"] == 1
        s2.close()

    with tempfile.TemporaryDirectory(prefix="tru-market-01c0-") as td:
        db = Path(td) / "market.sqlite3"
        t0 = 2_100_000_000

        closed = MarketStore(db)
        created = closed.post(sample_intent(), ts=t0)
        advert = created["advert"]
        owner = created["ownerToken"]
        try:
            closed.reserve(advert["advertId"], ts=t0 + 1)
            raise AssertionError("reservation write enabled by default")
        except RuntimeError as exc:
            assert "reservation writes disabled" in str(exc)
        assert len(closed.list_active(ts=t0 + 1)) == 1
        closed.close()

        rstore = MarketStore(db, reservation_write_enabled=True)
        held = rstore.reserve(
            advert["advertId"], hold_seconds=120, ts=t0 + 2
        )
        reservation = held["reservation"]
        reservation_token = held["reservationToken"]
        handoff = held["handoff"]
        assert reservation["status"] == "HELD"
        assert handoff["freshSwapRequired"] is True
        assert handoff["preexistingSwapIdAllowed"] is False
        assert handoff["makerGiveChain"] == "tru"
        assert handoff["makerGetChain"] == "bsty"
        assert handoff["takerGiveChain"] == "bsty"
        assert handoff["takerGetChain"] == "tru"
        assert rstore.list_active(ts=t0 + 3) == []

        raw = db.read_bytes()
        assert reservation_token.encode() not in raw

        try:
            rstore.reserve(advert["advertId"], ts=t0 + 4)
            raise AssertionError("double reservation accepted")
        except RuntimeError as exc:
            assert "open reservation" in str(exc)

        try:
            rstore.release_reservation(
                reservation["reservationId"], secure_reservation_token(), ts=t0 + 5
            )
            raise AssertionError("wrong reservation token released hold")
        except RuntimeError as exc:
            assert "reservation token rejected" in str(exc)

        try:
            rstore.withdraw(advert["advertId"], owner, ts=t0 + 6)
            raise AssertionError("maker withdrew held advert")
        except RuntimeError as exc:
            assert "reservation is HELD" in str(exc)

        fetched_handoff = rstore.reservation_handoff(
            reservation["reservationId"], reservation_token, ts=t0 + 7
        )
        assert fetched_handoff == handoff
        handoff_blob = json.dumps(fetched_handoff, sort_keys=True)
        for forbidden in (
            "ownerToken", "reservationToken", "private", "preimage",
            "claimPubkey", "refundPubkey", "destination",
        ):
            assert forbidden not in handoff_blob

        released = rstore.release_reservation(
            reservation["reservationId"], reservation_token, ts=t0 + 8
        )
        assert released["status"] == "RELEASED"
        assert len(rstore.list_active(ts=t0 + 9)) == 1

        held2 = rstore.reserve(
            advert["advertId"], hold_seconds=30, ts=t0 + 10
        )
        assert rstore.list_active(ts=t0 + 11) == []
        assert len(rstore.list_active(ts=t0 + 41)) == 1
        row_exp = rstore.conn.execute(
            "SELECT status FROM reservations WHERE reservation_id=?",
            (held2["reservation"]["reservationId"],),
        ).fetchone()
        assert row_exp["status"] == "EXPIRED"

        held3 = rstore.reserve(
            advert["advertId"], hold_seconds=120, ts=t0 + 42
        )
        swap_id = "ab" * 32
        bound = rstore.bind_reservation_to_fresh_swap(
            held3["reservation"]["reservationId"],
            held3["reservationToken"],
            swap_id,
            ts=t0 + 43,
        )
        assert bound["status"] == "BOUND"
        assert bound["swapId"] == swap_id
        assert rstore.list_active(ts=t0 + 44) == []

        try:
            rstore.release_reservation(
                held3["reservation"]["reservationId"],
                held3["reservationToken"],
                ts=t0 + 45,
            )
            raise AssertionError("bound reservation released")
        except RuntimeError as exc:
            assert "not held: BOUND" in str(exc)

        try:
            rstore.withdraw(advert["advertId"], owner, ts=t0 + 46)
            raise AssertionError("maker withdrew bound advert")
        except RuntimeError as exc:
            assert "reservation is BOUND" in str(exc)

        counts = rstore.counts(ts=t0 + 47)
        assert counts["RESERVATION_RELEASED"] == 1
        assert counts["RESERVATION_EXPIRED"] == 1
        assert counts["RESERVATION_BOUND"] == 1
        assert counts["RESERVATION_HELD"] == 0
        rstore.close()

    with tempfile.TemporaryDirectory(prefix="tru-market-01c1-relay-") as td:
        db = Path(td) / "market.sqlite3"
        t0 = 2_200_000_000
        rs = MarketStore(db, reservation_write_enabled=True)
        made = rs.post(sample_intent(baseAtoms="22200000000"), ts=t0)
        aid, owner = made["advert"]["advertId"], made["ownerToken"]
        held = rs.reserve(aid, hold_seconds=30, ts=t0 + 1)
        rid, rtok = held["reservation"]["reservationId"], held["reservationToken"]

        def blob(prefix, obj):
            raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
            return prefix + base64.b64encode(raw).decode()

        offer = blob(OFFER_PREFIX_V2, {"offerId": "11" * 32, "secretHash160": "22" * 20})
        accept = blob(ACCEPT_PREFIX_V2, {"offerId": "11" * 32, "acceptId": "33" * 32})
        final = blob(FINAL_PREFIX_V2, {"offerId": "11" * 32, "acceptId": "33" * 32, "recordParams": {"pairId": "TRU_BSTY"}})

        try:
            rs.submit_maker_offer(aid, owner, rid, blob(OFFER_PREFIX_V2, {"preimageHex": "00"}), ts=t0 + 2)
            raise AssertionError("secret-like handshake relay accepted")
        except RuntimeError as exc:
            assert "secret-like key" in str(exc)

        a = rs.submit_maker_offer(aid, owner, rid, offer, ts=t0 + 3)
        assert a["makerOffer"] == offer
        assert rs.submit_maker_offer(aid, owner, rid, offer, ts=t0 + 4)["makerOffer"] == offer
        try:
            rs.submit_maker_offer(aid, owner, rid, offer + "A", ts=t0 + 5)
            raise AssertionError("conflicting maker offer replay accepted")
        except RuntimeError:
            pass

        t = rs.reservation_status(rid, rtok, ts=t0 + 6)
        assert t["reservation"]["makerOffer"] == offer
        rs.submit_taker_accept(rid, rtok, accept, ts=t0 + 7)
        started = rs.mark_finalization_started(aid, owner, rid, ts=t0 + 8)
        assert started["finalizationStartedAt"] == t0 + 8

        # Once action intent is durable, expiry and release must fail closed.
        still = rs.reservation_status(rid, rtok, ts=t0 + 100)
        assert still["reservation"]["status"] == "HELD"
        try:
            rs.release_reservation(rid, rtok, ts=t0 + 101)
            raise AssertionError("post-finalization-start reservation released")
        except RuntimeError as exc:
            assert "canonical evidence reconciliation required" in str(exc)

        sid = "44" * 32
        rs.submit_maker_final(aid, owner, rid, final, sid, ts=t0 + 102)
        try:
            rs.acknowledge_taker_and_bind(rid, rtok, "55" * 32, ts=t0 + 103)
            raise AssertionError("mismatched taker swapId bound")
        except RuntimeError as exc:
            assert "maker/taker swapId mismatch" in str(exc)
        bound = rs.acknowledge_taker_and_bind(rid, rtok, sid, ts=t0 + 104)
        assert bound["status"] == "BOUND" and bound["swapId"] == sid
        idem = rs.acknowledge_taker_and_bind(rid, rtok, sid, ts=t0 + 105)
        assert idem["status"] == "BOUND" and idem["swapId"] == sid

        raw = db.read_bytes()
        assert owner.encode() not in raw and rtok.encode() not in raw
        rs.close()

    print("MARKET_01C1_HANDSHAKE_RELAY_SELFTEST=PASS")
    print("FINALIZATION_INTENT_BEFORE_RECORD_RESULT=PASS")
    print("POST_FINALIZATION_EXPIRY_REOPEN=FORBIDDEN")
    print("POST_FINALIZATION_RELEASE=FORBIDDEN")
    print("MAKER_TAKER_SWAP_ID_EQUALITY=REQUIRED")
    print("HANDSHAKE_CONFLICT_REPLAY=REJECTED")
    print("HANDSHAKE_SECRET_KEY_RELAY=REJECTED")
    print("MARKET_01C0_RESERVATION_SELFTEST=PASS")
    print("RESERVATION_DEFAULT_FAIL_CLOSED=PASS")
    print("ATOMIC_SINGLE_OPEN_RESERVATION=PASS")
    print("RESERVATION_TOKEN_HASH_ONLY=PASS")
    print("HELD_ADVERT_HIDDEN_FROM_BOOK=PASS")
    print("RESERVATION_EXPIRY_REOPENS_ADVERT=PASS")
    print("BOUND_ADVERT_REMAINS_HIDDEN=PASS")
    print("MAKER_WITHDRAW_DURING_RESERVATION=REJECTED")
    print("FRESH_SWAP_HANDOFF_NO_SECRET_MATERIAL=PASS")
    print("FRESH_SWAP_BIND_CONTRACT=PASS")

    print("MARKET_01A1_STORE_SELFTEST=PASS")
    print("ATOMIC_POST_LIST_WITHDRAW=PASS")
    print("OWNER_TOKEN_HASH_ONLY=PASS")
    print("WRONG_OWNER_TOKEN=REJECTED")
    print("DUPLICATE_ACTIVE_INTENT=REJECTED")
    print("EXPIRATION_MATERIALIZATION=PASS")
    print("RESTART_PERSISTENCE=PASS")
    print("PLANNED_PAIR_POST=REJECTED")
    print("NETWORK_LISTENER=NONE")
    print("PUBLIC_RESERVATION_ROUTE=STORE_READY_FOR_HTTP_ACTIVATION")
    print("SWAP_CREATION=LOCAL_AGENT_HANDSHAKE_ONLY")
    print("COIN_MOVEMENT=NONE")


def init_db(path: str) -> None:
    s = MarketStore(path)
    meta = dict(s.conn.execute("SELECT k,v FROM market_meta").fetchall())
    s.close()
    print("MARKET_DB_INIT=PASS")
    print(f"STORE_VERSION={meta.get('storeVersion')}")
    print(f"SCHEMA_VERSION={meta.get('schemaVersion')}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--init-db")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0
    if args.init_db:
        init_db(args.init_db)
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

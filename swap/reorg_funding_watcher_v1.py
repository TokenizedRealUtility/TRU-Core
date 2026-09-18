#!/usr/bin/env python3
"""REORG-SWAP-01D: read-only TRU funding observer owned by Agent serve.

Canonical journal: SELECT through a mode=ro connection, public columns only.
Writes: dedicated 01B/01C reorg sidecar. No funding/exit/swap-state mutations.
CONFIRMED and RECORDED rows stay eligible regardless of canonical swap state.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import threading
import time
from typing import Any

from reorg_funding_overlay_v1 import ReorgFundingOverlayStore

VERSION = 'TRU-REORG-SWAP-01D'
POLL_SECONDS = 10
BATCH_SIZE = 32
RPC_TIMEOUT_SECONDS = 10
DB_TIMEOUT_SECONDS = 5
SHUTDOWN_TIMEOUT_SECONDS = RPC_TIMEOUT_SECONDS + 20
HEX64 = re.compile(r'^[0-9a-f]{64}$')


class ObservationError(RuntimeError):
    """A fixed public error code, never an RPC error body or credential."""


class StopObservation(Exception):
    pass


class ReadOnlyTruRPC:
    """Use the existing tru-cli cookie/auth contract with a strict read allowlist."""
    def __init__(self, cli, conf, stop_event):
        self.cli = str(Path(cli).expanduser())
        self.conf = str(Path(conf).expanduser())
        self.stop_event = stop_event

    def __call__(self, method, params):
        if self.stop_event.is_set():
            raise StopObservation()
        key = {'swaprecordget': 'swapId', 'gettransaction': 'txid'}.get(method)
        if key is None or not isinstance(params, dict) or set(params) != {key}:
            raise ObservationError('RPC_METHOD_OR_PARAMETERS_FORBIDDEN')
        value = params[key]
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            raise ObservationError('RPC_IDENTITY_INVALID')
        request = dict(params)
        if method == 'swaprecordget':
            token = os.environ.get('TRU_SWAP_RPC_TOKEN', '')
            if len(token) < 32:
                raise ObservationError('RECORD_AUTH_UNAVAILABLE')
            request['authToken'] = token
        command = [self.cli, '-conf=' + self.conf, '-json', 'raw', method,
                   json.dumps(request, separators=(',', ':'))]
        try:
            cp = subprocess.run(command, text=True, capture_output=True,
                                timeout=RPC_TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired:
            raise ObservationError('RPC_TIMEOUT') from None
        except Exception:
            raise ObservationError('RPC_UNAVAILABLE') from None
        if self.stop_event.is_set():
            raise StopObservation()
        if cp.returncode != 0:
            raise ObservationError('RPC_FAILED')
        try:
            result = json.loads(cp.stdout)
        except (ValueError, TypeError):
            raise ObservationError('RPC_RESPONSE_INVALID') from None
        if not isinstance(result, dict) or result.get('error') is not None:
            raise ObservationError('RPC_RESPONSE_INVALID')
        return result


def readonly_journal(path):
    # URI quoting comes from Path.as_uri, including spaces and URI punctuation.
    conn = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True,
                           timeout=DB_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA query_only=ON')
    return conn


def terminal_page(journal_path, cursor='', limit=BATCH_SIZE):
    if not isinstance(cursor, str):
        raise ObservationError('JOURNAL_CURSOR_INVALID')
    if type(limit) is not int or not 1 <= limit <= BATCH_SIZE:
        raise ObservationError('JOURNAL_BATCH_INVALID')
    # Deliberately exclude prepared_raw_tx_hex, secrets, and swap_views filters.
    conn = readonly_journal(journal_path)
    try:
        rows = conn.execute('''
            SELECT operation_id AS operationId, swap_id AS swapId, chain,
                   amount_atoms AS amountAtoms,
                   expected_contract_commitment AS expectedContractCommitment,
                   starting_height AS startingHeight, state, txid, vout,
                   confirmations, prepared_txid AS preparedTxid,
                   prepared_contract_vout AS preparedContractVout,
                   prepared_payload_sha256 AS preparedPayloadSha256
              FROM funding_attempts
             WHERE chain='tru' AND state IN ('CONFIRMED','RECORDED')
               AND operation_id > ?
             ORDER BY operation_id LIMIT ?
        ''', (cursor, limit)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def validate_sidecar_path(journal_path, sidecar_path):
    if not journal_path.is_file():
        raise ObservationError('JOURNAL_UNAVAILABLE')
    if sidecar_path.resolve() == journal_path.resolve():
        raise ObservationError('SIDECAR_JOURNAL_COLLISION')
    for suffix in ('', '-wal', '-shm', '.observer.lock'):
        p = Path(str(sidecar_path) + suffix)
        if p.is_symlink():
            raise ObservationError('SIDECAR_SYMLINK_FORBIDDEN')
        if p.exists():
            st = p.stat()
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ObservationError('SIDECAR_FILE_ALIAS_FORBIDDEN')
    if sidecar_path.exists():
        if os.path.samefile(journal_path, sidecar_path):
            raise ObservationError('SIDECAR_JOURNAL_COLLISION')
        if sidecar_path.stat().st_size:
            conn = sqlite3.connect(sidecar_path.as_uri() + '?mode=ro', uri=True,
                                   timeout=DB_TIMEOUT_SECONDS)
            try:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                expected = {'funding_reorg_overlay', 'funding_reorg_events', 'sqlite_sequence'}
                if not tables.issubset(expected):
                    raise ObservationError('SIDECAR_FOREIGN_DATABASE_FORBIDDEN')
            finally:
                conn.close()


class FundingReorgWatcher:
    """One worker/one SQLite owner; stop-aware batches and public health counters."""
    def __init__(self, journal_path, reconcile, cli, conf):
        self.journal_path = Path(journal_path).expanduser().resolve()
        self.sidecar_path = self.journal_path.with_name(self.journal_path.name + '.funding-reorg.sqlite3')
        self.reconcile = reconcile
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.rpc = ReadOnlyTruRPC(cli, conf, self.stop_event)
        self._thread = None
        self._lock = threading.RLock()
        self._cursor = ''
        self._status = {
            'version': VERSION, 'installed': True, 'running': False,
            'ready': False, 'pollSeconds': POLL_SECONDS, 'batchSize': BATCH_SIZE,
            'cycles': 0, 'observed': 0, 'errors': 0,
            'lastCycleMs': None, 'lastSuccessMs': None, 'lastErrorCode': None,
            'canonicalJournalMutation': False, 'automaticBroadcast': False,
            'freshFundingAllowed': False, 'exitReorgRecovery': False,
        }

    def status(self):
        with self._lock:
            return dict(self._status)

    def _update(self, **fields):
        with self._lock:
            self._status.update(fields)

    def _error(self, code):
        with self._lock:
            self._status['errors'] += 1
            self._status['lastErrorCode'] = code

    def observe_batch(self, overlay):
        rows = terminal_page(self.journal_path, self._cursor)
        observed = errors = 0
        for attempt in rows:
            if self.stop_event.is_set():
                break
            try:
                record = self.rpc('swaprecordget', {'swapId': attempt['swapId']})
                if self.stop_event.is_set():
                    break
                result = self.reconcile(record, attempt, self.rpc, overlay_store=overlay)
                if result.get('classification') != 'TERMINAL_REORG_OBSERVATION':
                    raise ObservationError('TERMINAL_CLASSIFICATION_INVALID')
                observed += 1
                self._update(lastSuccessMs=int(time.time() * 1000))
            except StopObservation:
                break
            except Exception:
                if self.stop_event.is_set():
                    break
                # A failed read is neither absence nor a successful observation.
                # Advance to the next row so one bad swap cannot starve others.
                errors += 1
                self._error('TERMINAL_OBSERVATION_FAILED')
            self._cursor = attempt['operationId']
        if not self.stop_event.is_set() and len(rows) < BATCH_SIZE:
            self._cursor = ''
        with self._lock:
            self._status['cycles'] += 1
            self._status['observed'] += observed
            self._status['lastCycleMs'] = int(time.time() * 1000)
            if errors == 0 and not self.stop_event.is_set():
                self._status['lastErrorCode'] = None
        return {'observed': observed, 'errors': errors}

    def start(self):
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self.stop_event.clear()
            self.ready_event.clear()
            self._thread = threading.Thread(target=self._run,
                                            name='tru-funding-reorg-observer', daemon=True)
            self._thread.start()
        if not self.ready_event.wait(20):
            self.stop()
            raise ObservationError('REORG_OBSERVER_START_TIMEOUT')
        if not self.status()['ready']:
            self.stop()
            raise ObservationError('REORG_OBSERVER_START_FAILED')

    def stop(self):
        self.stop_event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(SHUTDOWN_TIMEOUT_SECONDS)
            if thread.is_alive():
                raise ObservationError('REORG_OBSERVER_STOP_TIMEOUT')

    def _run(self):
        overlay = None
        lock_fd = None
        try:
            validate_sidecar_path(self.journal_path, self.sidecar_path)
            lock_fd = os.open(str(self.sidecar_path) + '.observer.lock',
                              os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Recheck after locking; never open the canonical journal as a store.
            validate_sidecar_path(self.journal_path, self.sidecar_path)
            overlay = ReorgFundingOverlayStore(self.sidecar_path)
            self._update(running=True, ready=True, lastErrorCode=None)
            self.ready_event.set()
            while not self.stop_event.is_set():
                try:
                    self.observe_batch(overlay)
                except Exception:
                    self._error('JOURNAL_OR_SIDECAR_UNAVAILABLE')
                self.stop_event.wait(POLL_SECONDS)
        except Exception:
            self._error('REORG_OBSERVER_START_FAILED')
        finally:
            try:
                if overlay is not None:
                    overlay.close()
            finally:
                if lock_fd is not None:
                    os.close(lock_fd)
                self._update(running=False, ready=False)
                self.ready_event.set()

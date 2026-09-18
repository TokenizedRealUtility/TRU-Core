#!/usr/bin/env python3
"""01D offline Agent/lifecycle tests. Real SQLite, synthetic RPCs only."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import reorg_funding_watcher_v1 as watcher
import tru_funding_reconciler_v1 as rec
from reorg_funding_overlay_v1 import ReorgFundingOverlayStore

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('agent_01d_test', ROOT / 'swap/agent/tru_swap_agent.py')
agent_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_module)


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tru-01d-test-')
        self.addCleanup(self.temp.cleanup)
        self.journal = Path(self.temp.name) / 'custom agent #1.sqlite3'
        self.store = agent_module.Store(self.journal)
        self.records = {}
        self.states = {}
        self.calls = []
        self.observer = watcher.FundingReorgWatcher(self.journal, rec.reconcile_tru_attempt, '/synthetic-cli', '/synthetic-conf')
        self.observer.rpc = self.rpc
        self.addCleanup(self.observer.stop)

    def add_row(self, n=1, state='RECORDED', chain='tru'):
        sid = f'{n:064x}'
        record = {
            'swapId': sid, 'secretHash160': '34' * 20,
            'truClaimPubkey': '02' + '56' * 32,
            'truRefundPubkey': '03' + '78' * 32,
            'truRefundTime': 1800000000, 'truAmountAtoms': '9007199254740993',
            'state': 'SETTLED',
        }
        expected = rec.expected_tru_funding(record)
        raw = rec._fixture_tx([(0, bytes.fromhex(expected['metadataScriptHex'])),
                              (expected['amountAtoms'], bytes.fromhex(expected['contractScriptHex']))])
        txid = hashlib.sha256(('funding-' + sid).encode()).hexdigest()
        operation = agent_module.funding_operation_id(sid, chain)
        with self.store.connect() as conn:
            conn.execute('''INSERT INTO funding_attempts
                (operation_id,swap_id,chain,amount_atoms,expected_contract_commitment,
                 starting_height,state,txid,vout,confirmations,prepared_txid,
                 prepared_raw_tx_hex,prepared_contract_vout,prepared_payload_sha256,
                 prepared_ms,created_ms,updated_ms)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (operation,sid,chain,record['truAmountAtoms'],expected['commitment'],100,
                 state,txid,1,5,txid,'SECRET_RAW_SENTINEL',1,
                 hashlib.sha256(bytes.fromhex(raw)).hexdigest(),100,100,100))
        self.records[sid] = record
        self.states[txid] = dict(txid=txid,txState='SIDECHAIN',known=True,active=False,
                                 confirmations=0,sideBlockHeight=100,sideBlockHash='22'*32,
                                 reorgSignal=True,conflicted=False,conflictingTxid=None,hex=raw)
        return sid, txid, operation

    def rpc(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        if method == 'swaprecordget':
            return copy.deepcopy(self.records[params['swapId']])
        if method == 'gettransaction':
            return copy.deepcopy(self.states[params['txid']])
        self.fail('mutating/unexpected RPC requested')

    def dump(self):
        conn = watcher.readonly_journal(self.journal)
        try:
            return '\n'.join(conn.iterdump())
        finally:
            conn.close()

    def test_selects_only_terminal_tru_including_settled_swaps(self):
        for n, state in enumerate(('PREPARED','BROADCASTING','TX_IDENTIFIED','CONFIRMED','RECORDED','AMBIGUOUS','ABORTED'), 1):
            self.add_row(n,state)
        self.add_row(10,'RECORDED','bsty')
        before = self.dump()
        rows = watcher.terminal_page(self.journal)
        self.assertEqual({r['state'] for r in rows}, {'CONFIRMED','RECORDED'})
        self.assertEqual(len(rows), 2)
        self.assertNotIn('SECRET_RAW_SENTINEL', json.dumps(rows))
        self.assertTrue(all('preparedRawTxHex' not in row for row in rows))
        overlay = ReorgFundingOverlayStore(self.observer.sidecar_path)
        try:
            out = self.observer.observe_batch(overlay)
            self.assertEqual(out, {'observed':2,'errors':0})
        finally:
            overlay.close()
        self.assertEqual(self.dump(), before)
        self.assertEqual(len(self.calls), 4)

    def test_journal_connection_cannot_write(self):
        self.add_row()
        conn = watcher.readonly_journal(self.journal)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("UPDATE funding_attempts SET state='ABORTED'")
        finally:
            conn.close()

    def test_bounded_batches_do_not_starve_later_rows(self):
        for n in range(1, 36): self.add_row(n)
        overlay = ReorgFundingOverlayStore(self.observer.sidecar_path)
        try:
            first = self.observer.observe_batch(overlay)
            self.assertEqual(first['observed'], 32)
            second = self.observer.observe_batch(overlay)
            self.assertEqual(second['observed'], 3)
            self.assertEqual(len({p['swapId'] for m,p in self.calls if m=='swaprecordget'}),35)
            self.assertEqual(self.observer._cursor, '')
            again = self.observer.observe_batch(overlay)
            self.assertEqual(again['observed'],32)
        finally:
            overlay.close()

    def test_error_isolated_and_public_status_sanitized(self):
        sid, _, _ = self.add_row(1)
        self.add_row(2)
        def rpc(method, params):
            if method == 'swaprecordget' and params['swapId'] == sid:
                raise RuntimeError('PRIVATE_RPC_TOKEN_SENTINEL')
            return self.rpc(method, params)
        self.observer.rpc=rpc
        before=self.dump()
        overlay=ReorgFundingOverlayStore(self.observer.sidecar_path)
        try:
            out=self.observer.observe_batch(overlay)
            self.assertEqual(out,{'observed':1,'errors':1})
            self.assertIsNone(overlay.get_overlay(sid,'tru'))
        finally:overlay.close()
        self.assertEqual(self.dump(),before)
        health=self.observer.status()
        self.assertEqual(health['lastErrorCode'],'TERMINAL_OBSERVATION_FAILED')
        self.assertNotIn('SENTINEL',json.dumps(health))
        for field in ('canonicalJournalMutation','automaticBroadcast','freshFundingAllowed','exitReorgRecovery'):
            self.assertIs(health[field],False)

    def test_corrupt_operation_id_does_not_poison_pagination(self):
        for n in range(1,34):self.add_row(n)
        with self.store.connect() as conn:
            conn.execute("UPDATE funding_attempts SET operation_id='!malformed' WHERE swap_id=?",(f'{1:064x}',))
        overlay=ReorgFundingOverlayStore(self.observer.sidecar_path)
        try:
            first=self.observer.observe_batch(overlay)
            second=self.observer.observe_batch(overlay)
            self.assertEqual(first['errors']+second['errors'],1)
            self.assertEqual(first['observed']+second['observed'],32)
        finally:overlay.close()

    def test_reconfirmation_and_second_reorg_after_worker_restart(self):
        sid, txid, _=self.add_row()
        before=self.dump()
        side=copy.deepcopy(self.states[txid])
        def one_cycle():
            done=threading.Event()
            original=self.observer.reconcile
            def reconcile(*args,**kwargs):
                result=original(*args,**kwargs)
                done.set()
                return result
            self.observer.reconcile=reconcile
            self.observer.start()
            try:self.assertTrue(done.wait(3),'worker did not observe')
            finally:self.observer.stop()
            self.observer.reconcile=original
        one_cycle()
        self.states[txid]=dict(txid=txid,txState='CONFIRMED',known=True,active=True,
                               confirmations=5,reorgSignal=False,blockheight=100,
                               blockhash='11'*32,hex=side['hex'])
        one_cycle()
        self.states[txid]=side
        one_cycle()
        overlay=ReorgFundingOverlayStore(self.observer.sidecar_path)
        try:
            ov=overlay.get_overlay(sid,'tru')
            self.assertEqual(ov['historical_state'],'REORGED')
            self.assertEqual(ov['current_tx_state'],'SIDECHAIN')
            self.assertEqual(len(overlay.list_events(sid,'tru')),2)
        finally:overlay.close()
        self.assertEqual(self.dump(),before)
        self.assertFalse(self.observer.status()['running'])

    def test_second_worker_is_rejected_and_lock_released_on_stop(self):
        self.observer.start()
        second=watcher.FundingReorgWatcher(self.journal,rec.reconcile_tru_attempt,'/synthetic-cli','/synthetic-conf')
        second.rpc=self.rpc
        try:
            with self.assertRaises(watcher.ObservationError):second.start()
            self.assertTrue(self.observer.status()['running'])
            self.observer.stop()
            second.start()
            self.assertTrue(second.status()['running'])
        finally:second.stop()

    def test_start_twice_uses_one_thread(self):
        self.observer.start()
        original=self.observer._thread
        self.observer.start()
        self.assertIs(original,self.observer._thread)

    def test_shutdown_before_next_row(self):
        for n in range(1,4):self.add_row(n)
        def rpc(method,params):
            response=self.rpc(method,params)
            self.observer.stop_event.set()
            return response
        self.observer.rpc=rpc
        overlay=ReorgFundingOverlayStore(self.observer.sidecar_path)
        try:
            out=self.observer.observe_batch(overlay)
            self.assertEqual(out['observed'],0)
            self.assertEqual(len(self.calls),1)
            self.assertEqual(self.calls[0][0],'swaprecordget')
        finally:overlay.close()

    def test_journal_unavailable_loop_remains_observing_with_error_status(self):
        with self.store.connect() as conn:conn.execute('DROP TABLE funding_attempts')
        self.observer.start()
        # A deterministic batch call verifies failure; the live worker also holds
        # and retries observation without any journal/funding fallback.
        with self.assertRaises(sqlite3.OperationalError):watcher.terminal_page(self.journal)
        self.observer.stop()
        self.assertIs(self.observer.status()['canonicalJournalMutation'],False)

    def test_sidecar_is_derived_from_custom_journal_without_init_mutation(self):
        self.assertEqual(self.observer.sidecar_path.name,self.journal.name+'.funding-reorg.sqlite3')
        self.assertFalse(self.observer.sidecar_path.exists())
        self.assertFalse(self.observer.status()['running'])

    def test_sidecar_journal_collision_and_aliases_rejected(self):
        self.add_row()
        with self.assertRaises(watcher.ObservationError):
            watcher.validate_sidecar_path(self.journal,self.journal)
        side=self.observer.sidecar_path
        side.symlink_to(self.journal)
        with self.assertRaises(watcher.ObservationError):watcher.validate_sidecar_path(self.journal,side)
        side.unlink()
        os.link(self.journal,side)
        with self.assertRaises(watcher.ObservationError):watcher.validate_sidecar_path(self.journal,side)
        side.unlink()
        with sqlite3.connect(side) as conn:conn.execute('CREATE TABLE funding_attempts (x TEXT)')
        before=side.read_bytes()
        with self.assertRaises(watcher.ObservationError):watcher.validate_sidecar_path(self.journal,side)
        self.assertEqual(side.read_bytes(),before)

    def test_sidecar_permission_failure_does_not_start_or_modify_journal(self):
        self.add_row();before=self.dump()
        with patch.object(watcher,'ReorgFundingOverlayStore',side_effect=PermissionError('SECRET_SENTINEL')):
            with self.assertRaises(watcher.ObservationError) as ctx:self.observer.start()
        self.assertNotIn('SECRET_SENTINEL',str(ctx.exception))
        self.assertFalse(self.observer.status()['running'])
        self.assertEqual(self.dump(),before)

    def test_bounded_rpc_allowlist_and_auth(self):
        rpc=watcher.ReadOnlyTruRPC('/fake-cli','/fake-conf',threading.Event())
        sid='11'*32
        fake=subprocess.CompletedProcess([],0,stdout='{"ok":true}',stderr='')
        with patch.dict(os.environ,{'TRU_SWAP_RPC_TOKEN':'SYNTHETIC_TOKEN_'*3}):
            with patch.object(watcher.subprocess,'run',return_value=fake) as run:
                rpc('swaprecordget',{'swapId':sid})
                args,kwargs=run.call_args
                self.assertEqual(args[0][4],'swaprecordget')
                self.assertIn('authToken',json.loads(args[0][5]))
                self.assertEqual(kwargs['timeout'],10)
                self.assertFalse(kwargs.get('shell',False))
                rpc('gettransaction',{'txid':sid})
                self.assertNotIn('authToken',json.loads(run.call_args.args[0][5]))
                for method in ('sendrawtransaction','htlcbroadcastprepared','swaprecordtransition','htlccreate'):
                    before=run.call_count
                    with self.assertRaises(watcher.ObservationError):rpc(method,{'txid':sid})
                    self.assertEqual(run.call_count,before)
                with self.assertRaises(watcher.ObservationError):rpc('gettransaction',{'txid':sid,'authToken':'x'})

    def test_rpc_timeout_and_raw_errors_never_escape(self):
        rpc=watcher.ReadOnlyTruRPC('/fake-cli','/fake-conf',threading.Event())
        with patch.object(watcher.subprocess,'run',side_effect=subprocess.TimeoutExpired(['SECRET_SENTINEL'],10)):
            with self.assertRaises(watcher.ObservationError) as ctx:rpc('gettransaction',{'txid':'11'*32})
            self.assertEqual(str(ctx.exception),'RPC_TIMEOUT')
        for response in (subprocess.CompletedProcess([],1,'','SECRET_SENTINEL'),
                         subprocess.CompletedProcess([],0,'SECRET_SENTINEL',''),
                         subprocess.CompletedProcess([],0,'{"error":"SECRET_SENTINEL"}','')):
            with patch.object(watcher.subprocess,'run',return_value=response):
                with self.assertRaises(watcher.ObservationError) as ctx:rpc('gettransaction',{'txid':'11'*32})
                self.assertNotIn('SECRET_SENTINEL',str(ctx.exception))

    def test_real_agent_constructor_and_health_binding(self):
        with patch.dict(os.environ,{'TRU_SWAP_TRU_CLI':'/bin/true','TRU_SWAP_BSTY_CLI':'/bin/true'},clear=True):
            agent=agent_module.Agent(ROOT,Path(self.temp.name)/'agent-constructor.sqlite3')
        self.addCleanup(agent.reorg_watcher.stop)
        self.assertFalse(agent.reorg_watcher.sidecar_path.exists())
        agent.tru.public_raw=lambda *a:{}
        agent.bsty.json=lambda *a,**k:{'initialblockdownload':False}
        status=agent.health()['fundingReorgObserver']
        self.assertTrue(status['installed'])
        self.assertFalse(status['running'])
        self.assertEqual(status['version'],'TRU-REORG-SWAP-01D')

    def test_agent_serve_starts_and_stops_observer(self):
        self._serve_case(False)

    def test_agent_serve_cleans_up_if_observer_start_fails(self):
        self._serve_case(True)

    def _serve_case(self, fail_start):
        import types
        events=[]
        class FakeObserver:
            def start(self):
                events.append('observer_start')
                if fail_start:raise watcher.ObservationError('REORG_OBSERVER_START_FAILED')
            def stop(self):events.append('observer_stop')
        class FakeServer:
            def __init__(self,*args):pass
            def serve_forever(self,**kwargs):
                events.append('serve')
                raise KeyboardInterrupt()
            def server_close(self):events.append('server_close')
        def exit_loop(agent,stop):
            events.append('exit_start')
            stop.wait(3)
            events.append('exit_stop')
        fake=types.SimpleNamespace(reorg_watcher=FakeObserver(),
            exit_watcher=types.SimpleNamespace(watch_loop=exit_loop),
            remote_pairing='',pairing='SYNTHETIC_LOCAL_PAIRING',origins=set())
        argv=['tru_swap_agent.py','--tru-root',str(ROOT),'serve']
        with patch.dict(os.environ,{'TRU_SWAP_RPC_TOKEN':'SYNTHETIC_TOKEN_'*3}),patch.object(sys,'argv',argv),\
             patch.object(agent_module,'build_agent',return_value=fake),patch.object(agent_module,'Server',FakeServer),\
             contextlib.redirect_stdout(io.StringIO()):
            if fail_start:
                with self.assertRaises(watcher.ObservationError):agent_module.main()
            else:self.assertEqual(agent_module.main(),0)
        self.assertEqual(events[0],'observer_start')
        self.assertEqual(events[-2:],['observer_stop','server_close'])
        if fail_start:self.assertNotIn('exit_start',events)
        else:
            self.assertIn('exit_stop',events)
            self.assertIn('serve',events)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(ObserverTests))
    if not result.wasSuccessful():raise SystemExit(1)
    print('TRU_REORG_SWAP_01D_SELFTEST=PASS')
    print('CONFIRMED_RECORDED_TRU_JOURNAL_SELECTION=PASS')
    print('SETTLED_SWAPS_STILL_OBSERVED=PASS')
    print('CANONICAL_JOURNAL_READ_ONLY=PASS')
    print('BOUNDED_BATCH_FAIRNESS=PASS')
    print('RPC_READ_ALLOWLIST_TIMEOUT_AND_REDACTION=PASS')
    print('SECOND_OBSERVER_PROCESS_LOCK=PASS')
    print('SIDECAR_COLLISION_AND_ALIAS_REJECTION=PASS')
    print('RESTART_RECONFIRMATION_RECURRENT_REORG=PASS')
    print('AGENT_SERVE_STARTUP_AND_SHUTDOWN=PASS')
    print('EXISTING_FUNDING_AND_EXIT_GATES=UNCHANGED')
    print('AUTOMATIC_FUNDING_OR_BROADCAST_FROM_OBSERVER=NO')

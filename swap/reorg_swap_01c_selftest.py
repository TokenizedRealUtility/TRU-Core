#!/usr/bin/env python3
"""Offline integration regressions. Synthetic transactions and temporary DBs only."""
import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import tru_funding_reconciler_v1 as rec
from reorg_funding_overlay_v1 import ReorgFundingOverlayStore


class ReorgIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tru-reorg-01c-test-')
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'sidecar.sqlite3'
        self.store = ReorgFundingOverlayStore(self.db)
        self.addCleanup(lambda: self.store.close())
        self.record = {
            'swapId': '12' * 32, 'secretHash160': '34' * 20,
            'truClaimPubkey': '02' + '56' * 32,
            'truRefundPubkey': '03' + '78' * 32,
            'truRefundTime': 1800000000, 'truAmountAtoms': '9007199254740993',
        }
        self.expected = rec.expected_tru_funding(self.record)
        self.raw = rec._fixture_tx([
            (0, bytes.fromhex(self.expected['metadataScriptHex'])),
            (self.expected['amountAtoms'], bytes.fromhex(self.expected['contractScriptHex'])),
            (7, b'\x51'),
        ])
        self.txid = 'ab' * 32  # Opaque node-bound identity, not a computed TRU txid.
        self.attempt = {
            'operationId': hashlib.sha256(('TRU-SWAP-FUNDING-V1|' + self.record['swapId'] + '|tru').encode()).hexdigest(),
            'swapId': self.record['swapId'], 'chain': 'tru',
            'amountAtoms': self.record['truAmountAtoms'],
            'expectedContractCommitment': self.expected['commitment'],
            'startingHeight': 100, 'state': 'RECORDED', 'txid': self.txid,
            'vout': 1, 'confirmations': 5, 'preparedTxid': self.txid,
            'preparedContractVout': 1,
            'preparedPayloadSha256': hashlib.sha256(bytes.fromhex(self.raw)).hexdigest(),
        }

    def status(self, state):
        o = dict(txid=self.txid, txState=state, known=state != 'NOT_FOUND',
                 active=state == 'CONFIRMED', confirmations=5 if state == 'CONFIRMED' else 0,
                 reorgSignal=state in {'SIDECHAIN', 'CONFLICTED'})
        if state != 'NOT_FOUND':
            o['hex'] = self.raw
        if state == 'CONFIRMED':
            o.update(blockheight=100, blockhash='11' * 32)
        elif state in {'SIDECHAIN', 'CONFLICTED'}:
            o.update(sideBlockHeight=100, sideBlockHash='22' * 32,
                     conflicted=state == 'CONFLICTED',
                     conflictingTxid='cd' * 32 if state == 'CONFLICTED' else None)
        elif state == 'MEMPOOL':
            o.update(blockheight=None, blockhash=None)
        return o

    def observe(self, response, attempt=None, record=None, store=True, tick=1000):
        before = copy.deepcopy((self.record, self.attempt, response))
        calls = []
        def rpc(method, params):
            calls.append((method, params))
            self.assertEqual((method, params), ('gettransaction', {'txid': self.txid}))
            return response
        result = rec.reconcile_tru_attempt(
            self.record if record is None else record,
            self.attempt if attempt is None else attempt, rpc,
            max_scan_blocks=0, overlay_store=self.store if store else None, observed_ms=tick,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(before, (self.record, self.attempt, response))
        for flag in ('safeToRetry', 'sameTxRebroadcastEligible', 'freshFundingAllowed',
                     'automaticBroadcast', 'broadcast', 'journalMutation', 'swapStateMutation'):
            self.assertIs(result[flag], False)
        self.assertNotIn('candidate', result)
        self.assertEqual(result['classification'], 'TERMINAL_REORG_OBSERVATION')
        return result

    def test_all_five_states_both_terminal_states(self):
        for journal in ('CONFIRMED', 'RECORDED'):
            for state in ('CONFIRMED', 'MEMPOOL', 'SIDECHAIN', 'CONFLICTED', 'NOT_FOUND'):
                with self.subTest(journal=journal, state=state):
                    row = dict(self.attempt, state=journal)
                    out = self.observe(self.status(state), attempt=row, store=False)
                    self.assertEqual(out['journalState'], journal)
                    self.assertEqual(out['currentTxState'], state)
                    self.assertEqual(out['historicalState'], 'STABLE_CONFIRMED' if state == 'CONFIRMED' else 'REORGED')

    def test_stable_confirmed_and_depth_drop_no_overlay_noise(self):
        out = self.observe(self.status('CONFIRMED'))
        shallow = dict(self.status('CONFIRMED'), confirmations=1)
        out = self.observe(shallow)
        self.assertEqual(out['confirmations'], 1)
        self.assertFalse(out['overlayRecorded'])
        self.assertEqual(self.store.list_events(self.record['swapId'], 'tru'), [])

    def test_recurrent_evidence_after_reconfirmation_and_restart(self):
        self.observe(self.status('SIDECHAIN'), tick=1000)
        first = self.store.get_overlay(self.record['swapId'], 'tru')
        out = self.observe(self.status('CONFIRMED'), tick=2000)
        self.assertEqual(out['action'], 'RECOVERED_CONFIRMED')
        self.assertEqual(out['historicalState'], 'REORGED')
        self.store.close()
        self.store = ReorgFundingOverlayStore(self.db)
        for tick, state in enumerate(('SIDECHAIN', 'SIDECHAIN', 'CONFIRMED', 'SIDECHAIN'), 3000):
            out = self.observe(self.status(state), tick=tick)
            self.assertTrue(out['overlayDeduped'])
            self.assertEqual(out['currentTxState'], state)
            ov = self.store.get_overlay(self.record['swapId'], 'tru')
            self.assertEqual(ov['current_tx_state'], state)
            self.assertEqual(ov['action'], out['action'])
            self.assertEqual(ov['last_observed_ms'], tick)
            self.assertEqual(ov['first_reorg_ms'], first['first_reorg_ms'])
            self.assertEqual(ov['observation_count'], 2)
        self.assertEqual(len(self.store.list_events(self.record['swapId'], 'tru')), 2)

    def test_all_nonactive_states_persist(self):
        for state in ('MEMPOOL', 'SIDECHAIN', 'CONFLICTED', 'NOT_FOUND'):
            out = self.observe(self.status(state))
            self.assertTrue(out['overlayRecorded'])
            ov = self.store.get_overlay(self.record['swapId'], 'tru')
            self.assertEqual(ov['current_tx_state'], state)
        self.assertEqual(len(self.store.list_events(self.record['swapId'], 'tru')), 4)

    def test_identity_validation_precedes_rpc(self):
        cases = [dict(self.attempt, **fields) for fields in (
            {'operationId': '00' * 32}, {'swapId': '00' * 32}, {'chain': 'bsty'},
            {'amountAtoms': '10'}, {'expectedContractCommitment': '00' * 32},
            {'txid': None}, {'vout': 0}, {'vout': True}, {'preparedTxid': '00' * 32},
            {'preparedContractVout': True}, {'preparedPayloadSha256': 'broken'},
        )]
        for row in cases:
            with self.subTest(row=list(row.keys())):
                with self.assertRaises(rec.ReconcileError):
                    rec.reconcile_tru_attempt(self.record, row, lambda *a: self.fail('RPC before identity validation'))

    def test_canonical_record_identity_mismatch(self):
        for fields in ({'truFundingTxid': '00' * 32}, {'truFundingVout': 0},
                       {'evidence': {'truFundingTxid': '00' * 32}}, {'evidence': []}):
            with self.assertRaises(rec.ReconcileError):
                rec.reconcile_tru_attempt(dict(self.record, **fields), self.attempt,
                                          lambda *a: self.fail('RPC before identity validation'))

    def test_malformed_status_never_writes_overlay(self):
        cases = [None, {}, {'error': {'message': 'SECRET_SENTINEL'}},
                 {'result': self.status('CONFIRMED')}]
        cases += [dict(self.status('CONFIRMED'), **fields) for fields in (
            {'txid': '00' * 32}, {'txState': 'MISSING'}, {'txState': []},
            {'confirmations': -1}, {'confirmations': True}, {'confirmations': '5'},
            {'active': False}, {'known': 1}, {'reorgSignal': True},
            {'blockheight': None}, {'blockheight': True}, {'blockheight': 0},
            {'blockhash': None}, {'blockhash': 'BAD'}, {'hex': None}, {'hex': 'abc'},
            {'sideBlockHeight': 100}, {'conflictingTxid': 'cd' * 32},
        )]
        cases += [dict(self.status('SIDECHAIN'), conflicted=True),
                  dict(self.status('CONFLICTED'), conflictingTxid=self.txid),
                  dict(self.status('CONFLICTED'), conflictingTxid=None),
                  dict(self.status('MEMPOOL'), reorgSignal=None),
                  dict(self.status('NOT_FOUND'), known=True)]
        for response in cases:
            with self.subTest(response_type=type(response).__name__):
                with self.assertRaises(rec.ReconcileError) as ctx:
                    self.observe(response)
                self.assertNotIn('SECRET_SENTINEL', str(ctx.exception))
                self.assertEqual(self.store.list_events(self.record['swapId'], 'tru'), [])

    def test_transport_failure_does_not_mean_not_found(self):
        def rpc(*args):
            raise TimeoutError('SECRET_SENTINEL')
        with self.assertRaises(rec.ReconcileError) as ctx:
            rec.reconcile_tru_attempt(self.record, self.attempt, rpc, overlay_store=self.store)
        self.assertNotIn('SECRET_SENTINEL', str(ctx.exception))
        self.assertIsNone(self.store.get_overlay(self.record['swapId'], 'tru'))

    def test_raw_funding_output_and_prepared_digest_binding(self):
        for outputs in (
            [(0, b'\x6a\x00'), (self.expected['amountAtoms'], bytes.fromhex(self.expected['contractScriptHex']))],
            [(0, bytes.fromhex(self.expected['metadataScriptHex'])), (1, bytes.fromhex(self.expected['contractScriptHex']))],
            [(0, bytes.fromhex(self.expected['metadataScriptHex'])), (self.expected['amountAtoms'], b'\x51')],
            [(0, bytes.fromhex(self.expected['metadataScriptHex'])), (self.expected['amountAtoms'], bytes.fromhex(self.expected['contractScriptHex'])), (8, b'\x51')],
        ):
            with self.assertRaises(rec.ReconcileError):
                self.observe(dict(self.status('MEMPOOL'), hex=rec._fixture_tx(outputs)))

    def test_no_private_fields_returned_or_stored(self):
        row = dict(self.attempt, preparedRawTxHex=self.raw, preimage='SECRET_SENTINEL', privateKey='SECRET_SENTINEL')
        response = dict(self.status('SIDECHAIN'), preimage='SECRET_SENTINEL', rpcToken='SECRET_SENTINEL')
        out = self.observe(response, attempt=row)
        text = json.dumps(out) + '\n'.join(self.store.conn.iterdump())
        for forbidden in ('SECRET_SENTINEL', self.raw, 'preparedRawTxHex'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(out['action'], 'HOLD_UNKNOWN')

    def test_public_journal_without_prepared_material_is_observable(self):
        row = {k: v for k, v in self.attempt.items() if not k.startswith('prepared')}
        out = self.observe(self.status('NOT_FOUND'), attempt=row)
        self.assertEqual(out['action'], 'HOLD_UNKNOWN')
        self.assertTrue(out['overlayRecorded'])

    def test_overlay_identity_cannot_be_replaced(self):
        self.observe(self.status('SIDECHAIN'))
        original = '\n'.join(self.store.conn.iterdump())
        row = {'state': 'RECORDED', 'txid': 'ff' * 32}
        with self.assertRaises(ValueError):
            self.store.record_observation(swap_id=self.record['swapId'], chain='tru',
                                          durable_row=row, tx_status=self.status('SIDECHAIN'))
        self.assertEqual(original, '\n'.join(self.store.conn.iterdump()))

    def test_storage_failure_is_not_success(self):
        self.store.conn.execute("CREATE TRIGGER deny_write BEFORE INSERT ON funding_reorg_overlay BEGIN SELECT RAISE(ABORT, 'SECRET_SENTINEL'); END")
        with self.assertRaises(rec.ReconcileError) as ctx:
            self.observe(self.status('SIDECHAIN'))
        self.assertNotIn('SECRET_SENTINEL', str(ctx.exception))
        self.assertEqual(self.store.list_events(self.record['swapId'], 'tru'), [])

    def test_nonterminal_scanner_preserved(self):
        for state in ('PREPARED', 'BROADCASTING', 'TX_IDENTIFIED'):
            for count in (0, 1, 2):
                calls = []
                def rpc(method, params):
                    calls.append(method)
                    if method == 'getrawmempool':
                        return {('ab' if i == 0 else 'cd') * 32: {'vout': [
                            {'index': 0, 'amount': 0, 'scriptPubKey': self.expected['metadataScriptHex']},
                            {'index': 1, 'amount': self.expected['amountAtoms'], 'scriptPubKey': self.expected['contractScriptHex']},
                        ]} for i in range(count)}
                    if method == 'getblockcount': return 99
                    self.fail('unexpected RPC ' + method)
                out = rec.reconcile_tru_attempt(self.record, dict(self.attempt, state=state), rpc,
                                                overlay_store=self.store)
                self.assertEqual(out['classification'], ('ZERO_CANDIDATES', 'ONE_CANDIDATE', 'MULTIPLE_CANDIDATES')[count])
                self.assertFalse(out['safeToRetry'])
                self.assertEqual(calls, ['getrawmempool', 'getblockcount'])
                self.assertEqual(self.store.list_events(self.record['swapId'], 'tru'), [])

    def test_canonical_db_and_recorded_journal_unchanged(self):
        # A separate synthetic journal proves observation only receives a copy.
        db = Path(self.temp.name) / 'canonical.sqlite3'
        with sqlite3.connect(db) as conn:
            conn.execute('CREATE TABLE funding_attempts (state TEXT, payload TEXT)')
            conn.execute('INSERT INTO funding_attempts VALUES (?,?)', ('RECORDED', json.dumps(self.attempt)))
        before = db.read_bytes()
        with sqlite3.connect(f'file:{db}?mode=ro', uri=True) as conn:
            row = json.loads(conn.execute('SELECT payload FROM funding_attempts').fetchone()[0])
        for state in ('SIDECHAIN', 'MEMPOOL', 'CONFLICTED', 'NOT_FOUND', 'CONFIRMED'):
            self.observe(self.status(state), attempt=row)
        self.assertEqual(db.read_bytes(), before)
        self.assertEqual(row['state'], 'RECORDED')
        tables = {r[0] for r in self.store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn('funding_attempts', tables)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReorgIntegrationTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print('TRU_REORG_SWAP_01C_SELFTEST=PASS')
    print('FIVE_EXPLICIT_TX_STATES=PASS')
    print('TERMINAL_EXACT_TX_OBSERVATION=PASS')
    print('NONTERMINAL_SCANNER_REGRESSION=PASS')
    print('REPEATED_REORG_AFTER_RECONFIRMATION=PASS')
    print('OVERLAY_REOPEN_DURABILITY=PASS')
    print('RPC_FAILURE_AND_MALFORMED_STATUS=FAIL_CLOSED')
    print('CANONICAL_FUNDING_JOURNAL_MUTATION=NONE')
    print('RECORDED_TERMINAL_STATE=PRESERVED')
    print('PRIVATE_FIELDS_IN_OUTPUT_OR_OVERLAY=NONE')
    print('LIVE_AGENT_REORG_BINDING=DEFERRED_TO_01D')
    print('TX_BROADCAST=NO')

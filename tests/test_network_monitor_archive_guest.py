"""Portable contract checks for guarded archive VM exercise and receipt verification."""
import copy
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from scripts import network_monitor_archive_guest as guest


class ArchiveGuestTests(unittest.TestCase):
    def test_ordinary_harness_cannot_submit_fabricated_observations(self):
        with patch.object(guest.service, 'request') as request:
            with self.assertRaisesRegex(RuntimeError, 'fabricate'):
                guest.request('observe')
        request.assert_not_called()

    def test_guarded_worker_and_collector_have_separate_exact_units(self):
        monitor = guest.unit_text(guest.MONITOR_UNIT)
        collector = guest.unit_text(guest.COLLECTOR_UNIT)
        self.assertIn('network_monitor_archive_guest.py worker', monitor)
        self.assertIn('network_monitor_archive_collector.py serve', collector)
        self.assertNotIn('--allow-test-crashes', monitor)
        self.assertIn('Restart=on-failure', monitor)
        self.assertNotIn('Requires=' + guest.MONITOR_UNIT, collector)
        self.assertIn('ReadWritePaths=' + str(guest.STATE) + ' ' + str(guest.RUNTIME), monitor)
        self.assertIn('RestrictAddressFamilies=AF_UNIX', monitor)
        with self.assertRaises(RuntimeError):
            guest.unit_text('unrelated.service')

    def test_public_inventory_is_fixed_and_source_hashes_include_archive_dependencies(self):
        self.assertEqual(len(guest.PUBLIC_FILES), 12)
        self.assertEqual(len(set(guest.PUBLIC_FILES)), 12)
        self.assertEqual(guest.ARCHIVE_FILES, ('archive-segment-000001.json', 'archive-segment-000002.json'))
        hashes = guest.source_hashes()
        self.assertEqual(set(hashes), set(guest.SOURCE_FILES))
        self.assertIn('scripts/network_monitor_archive.py', hashes)
        self.assertIn('scripts/network_monitor_archive_collector.py', hashes)

    def recovery_values(self):
        incident = guest.reboot.CRITICAL + '#1'
        def status(pid, count):
            return {'process_id': pid, 'committed_count': count,
                    'alerts': [{'key': guest.reboot.CRITICAL, 'state': 'open', 'id': incident}]}
        before = {'status': status(100, 20), 'monitor_manager': {'NRestarts': 0},
                  'collector_manager': {'MainPID': 101, 'NRestarts': 0}}
        after = {'status': status(200, 129), 'monitor_manager': {'NRestarts': 1},
                 'collector_manager': {'MainPID': 101, 'NRestarts': 0}}
        return before, {'head_sequence': 128, 'process_id': 100, 'request_id': 'archive-boundary'}, {'NRestarts': 0}, status(200, 129), after, incident

    def test_recovery_success_does_not_read_logs_or_change_acceptance(self):
        with patch.object(guest, 'diagnostics') as diagnostics:
            guest.validate_recovery(*self.recovery_values())
        diagnostics.assert_not_called()

    def test_recovery_failure_identifies_restart_count_collector_and_incident_separately(self):
        for change, expected in (
            (lambda after: after['monitor_manager'].update(NRestarts=2), 'exactly_one_monitor_restart'),
            (lambda after: after['collector_manager'].update(MainPID=202, NRestarts=1), 'same_collector_process'),
            (lambda after: after['status']['alerts'][0].update(id=guest.reboot.CRITICAL + '#2'), 'snapshot_preserves_incident'),
            (lambda after: after['status'].update(process_id=201), 'wait_and_snapshot_same_monitor'),
        ):
            values = self.recovery_values()
            change(values[4])
            with patch.object(guest, 'diagnostics', return_value={'bounded': True}), \
                    patch.object(guest, 'collector_diagnostic', return_value={'bounded': True}):
                with self.assertRaisesRegex(RuntimeError, expected) as caught:
                    guest.validate_recovery(*values)
            self.assertIn('monitor_restart_counts', str(caught.exception))
            self.assertIn('collector_pids', str(caught.exception))
            self.assertIn('critical_ids', str(caught.exception))

    def test_failure_diagnostics_read_only_fixed_units_and_sanitize_bounded_logs(self):
        def run(arguments, **kwargs):
            if arguments[0] == 'systemctl':
                text = 'MainPID=123\nNRestarts=1\nResult=exit-code\nUnrequestedField=omit-me\nSubState=/var/private/secret\n'
            else:
                unit = arguments[-1].removeprefix('--unit=')
                text = ('private /var/private/secret ' + 'a' * 64 + '\n') * 100
                text += f'{unit}: Main process exited, code=killed, status=9/KILL\n'
                text += f'{unit}: Main process exited, code=killed, status=9/KILL /var/private/secret\n'
                text += 'Monitor request rejected: source_timestamp_before_boundary\n'
                text += 'Monitor request rejected: /var/private/secret\n'
            return subprocess.CompletedProcess(arguments, 0, text, '')
        with patch.object(guest, 'command', side_effect=run) as command:
            result = guest.diagnostics()
        self.assertEqual(set(result), {guest.MONITOR_UNIT, guest.COLLECTOR_UNIT})
        self.assertEqual(command.call_count, 4)
        for record in result.values():
            self.assertEqual(record['service'], {'MainPID': '123', 'NRestarts': '1', 'Result': 'exit-code'})
            self.assertIn('status=9/KILL', record['recent_log'])
            self.assertNotIn('/var/private/secret', record['recent_log'])
            self.assertNotIn('a' * 64, record['recent_log'])
            self.assertLessEqual(len(record['recent_log'].splitlines()), 12)
        self.assertTrue(all(call.kwargs['timeout'] == 5 for call in command.call_args_list))
        self.assertIn('source_timestamp_before_boundary', result[guest.MONITOR_UNIT]['recent_log'])
        self.assertNotIn('source_timestamp_before_boundary', result[guest.COLLECTOR_UNIT]['recent_log'])

    def test_collector_diagnostic_reports_shape_and_hash_without_observation_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve()
            path.chmod(0o700)
            pending = path / 'pending.json'
            pending.write_text(json.dumps({'process_id': 101, 'cycle': 127,
                                           'request': {'request_id': 'original-request', 'observation': {'private': 'omitted'}}}))
            pending.chmod(0o600)
            with patch.object(guest, 'PRIVATE', path), patch.object(guest.reboot, 'ordinary', side_effect=lambda p: p.stat()):
                result = guest.collector_diagnostic('original-request')
            self.assertTrue(result['pending.json']['matches_boundary_request'])
            self.assertEqual(result['pending.json']['cycle'], 127)
            self.assertEqual(len(result['pending.json']['request_id_sha256']), 64)
            self.assertNotIn('original-request', json.dumps(result))
            self.assertNotIn('observation', json.dumps(result))
            self.assertFalse(result['runtime.json']['exists'])

    def test_archived_retry_and_fresh_status_precede_stop_and_offline_export(self):
        order = []
        first = {'request': {'command': 'observe', 'request_id': 'archived-original', 'observation': {}},
                 'committed_sequence': 2, 'evaluation': {'status': 'unknown'}}
        final = {'committed_count': 275, 'head_digest': 'a' * 64, 'current_evaluation': {'status': 'healthy'}}
        stopped = {'ActiveState': 'inactive', 'MainPID': 0}
        def read_status(name):
            self.assertEqual(name, 'status')  # No full export is sent through the live socket.
            order.append('status')
            return copy.deepcopy(final)
        def retry(state, payload):
            self.assertEqual(payload, first['request'])
            order.append('exact_retry')
            return {'ok': True, 'duplicate': True, 'committed_sequence': 2, 'evaluation': first['evaluation']}
        def stop(arguments, **kwargs):
            self.assertEqual(arguments, ['systemctl', 'stop', guest.MONITOR_UNIT])
            order.append('stop')
        def offline(status, manager):
            self.assertEqual(status, final)
            self.assertEqual(manager, stopped)
            order.append('verified_offline_export')
            return {'ok': True, 'current_status': status}
        with patch.object(guest, 'request', side_effect=read_status), patch.object(guest.service, 'request', side_effect=retry), \
                patch.object(guest, 'command', side_effect=stop), patch.object(guest, 'manager', return_value=stopped), \
                patch.object(guest, 'offline_export', side_effect=offline):
            journal, captured, duplicate, observed_stop = guest.retry_and_stop(first)
        self.assertEqual(order, ['status', 'exact_retry', 'status', 'status', 'stop', 'verified_offline_export'])
        self.assertEqual(journal['current_status'], captured)
        self.assertEqual(duplicate['result']['committed_sequence'], 2)
        self.assertEqual(observed_stop, stopped)

    def test_offline_export_requires_stopped_service_and_exact_live_head(self):
        final = {'committed_count': 2, 'head_digest': 'b' * 64}
        stopped = {'ActiveState': 'inactive', 'MainPID': 0}
        verified = MagicMock()
        verified.total_count = 2
        verified.head_digest = final['head_digest']
        verified.export.return_value = {'rows': [{'row_digest': 'a' * 64}, {'row_digest': 'b' * 64}], 'history_complete': True}
        context = MagicMock()
        context.__enter__.return_value = verified
        with patch.object(guest.archive, 'ArchiveJournal', return_value=context) as opened:
            with self.assertRaisesRegex(RuntimeError, 'stopped'):
                guest.offline_export(final, {'ActiveState': 'active', 'MainPID': 123})
            opened.assert_not_called()
            result = guest.offline_export(final, stopped)
            self.assertEqual(result['current_status'], final)
            self.assertTrue(result['history_complete'])
            verified.total_count = 3
            with self.assertRaisesRegex(RuntimeError, 'last live'):
                guest.offline_export(final, stopped)
            verified.total_count = 2
            verified.head_digest = 'c' * 64
            with self.assertRaisesRegex(RuntimeError, 'last live'):
                guest.offline_export(final, stopped)

    def test_completion_failure_identifies_stage_without_dumping_requests(self):
        for stage in ('live_archived_retry', 'offline_verified_export', 'capture_validation', 'archive_refusal_checks'):
            def closed():
                raise ValueError('Connection closed before a complete response.')
            with self.assertRaisesRegex(RuntimeError, 'Archive stage ' + stage + ' failed: Connection closed'):
                guest.stage_call(stage, closed)
        with self.assertRaisesRegex(RuntimeError, 'Unknown'):
            guest.stage_call('unrelated', lambda: None)

    def inventory(self):
        rows, records = [], []
        for cycle in range(1, 271):
            sequence = cycle + 1 + (cycle >= 128) + (cycle >= 255)
            name = 'archive_' + 'a' * 32 + '_' + str(cycle)
            probes = []
            if guest.collector.canary_cycle(cycle):
                for index, (source, target, port) in enumerate(guest.automatic.monitoring.CANARIES):
                    probes.append({'from': source, 'to': target, 'port': port, 'destination_health': None,
                                   'source_port': guest.collector.PORT_START + 6 * (cycle - 1) + index})
            observation = {'phase': name, 'ruleset': {'nftables': []}, 'collection_error': None, 'probes': probes}
            payload = {'command': 'observe', 'request_id': name, 'observation': observation}
            evaluation = {'status': 'critical' if probes else 'unknown'}
            records.append({'instance_id': 'a' * 32, 'process_id': 123, 'cycle': cycle, 'request': payload,
                            'delivery_process_id': 123, 'committed_sequence': sequence, 'evaluation': evaluation,
                            'duplicate_acknowledgement': cycle in (127, 254),
                            'delivery_attempts': 2 if cycle in (127, 254) else 1,
                            'transport_failures': ['ConnectionResetError'] if cycle in (127, 254) else []})
            rows.append({'sequence': sequence, 'request_id': name, 'request': {'kind': 'observation', 'observation': observation},
                         'evaluation': evaluation})
        crashes = [{'boundary': {'request_id': records[c - 1]['request']['request_id'], 'request': records[c - 1]['request'],
                                'head_sequence': records[c - 1]['committed_sequence']}} for c in (127, 254)]
        return {'rows': rows}, records, crashes

    def test_inventory_binds_real_producer_receipts_canary_ports_and_both_retries(self):
        journal, records, crashes = self.inventory()
        probes = guest.validate_inventory(journal, records, crashes)
        self.assertEqual(len(probes), 51)
        broken = copy.deepcopy(records)
        broken[126]['duplicate_acknowledgement'] = False
        with self.assertRaisesRegex(RuntimeError, 'retried exactly'):
            guest.validate_inventory(journal, broken, crashes)
        broken = copy.deepcopy(journal)
        broken['rows'][0]['evaluation']['status'] = 'healthy'
        broken_records = copy.deepcopy(records)
        broken_records[0]['evaluation']['status'] = 'healthy'
        with self.assertRaisesRegex(RuntimeError, 'Rule-only'):
            guest.validate_inventory(broken, broken_records, crashes)
        broken = copy.deepcopy(records)
        broken[15]['request']['observation']['probes'][0]['source_port'] = 42006
        with self.assertRaises(RuntimeError):
            guest.validate_inventory(journal, broken, crashes)


    def collector_manager(self, pid=123, restarts=0, *, active='active', substate='running'):
        return {'MainPID': pid, 'NRestarts': restarts, 'ActiveState': active, 'SubState': substate,
                'ExecMainStartTimestampMonotonic': pid + 100, 'InvocationID': f'{pid:032x}'}

    def test_continuity_rejects_unexpected_restart_and_permits_clean_exit(self):
        continuity = guest.CollectorContinuity(inject=False)
        continuity.check(self.collector_manager())
        continuity.check(self.collector_manager(0, active='inactive', substate='dead'))
        for replacement in (self.collector_manager(0, 1, active='activating', substate='auto-restart'),
                            self.collector_manager(124, 1), self.collector_manager(124)):
            with self.assertRaisesRegex(guest.CollectorRestartError, 'collector_identity_verification') as caught:
                continuity.check(replacement)
            self.assertEqual(caught.exception.current, replacement)

    def test_late_inventory_preserves_mixed_producer_and_delivery_evidence(self):
        for field, value in (('process_id', 124), ('delivery_process_id', 124), ('instance_id', 'b' * 32)):
            journal, records, crashes = self.inventory()
            records[5][field] = value
            with self.assertRaisesRegex(guest.CollectorRestartError, 'receipt_history_verification') as caught:
                guest.stage_call('receipt_history_verification', lambda: guest.validate_inventory(journal, records, crashes))
            self.assertEqual(caught.exception.first['committed_sequence'], 2)
            self.assertEqual(caught.exception.differing['cycle'], 6)
            self.assertNotIn('request', caught.exception.differing)

    def test_guarded_injection_uses_normal_check_and_reports_bounded_signal_evidence(self):
        original, replacement = self.collector_manager(), self.collector_manager(124, 1)
        continuity = guest.CollectorContinuity(inject=True)
        continuity.check(original)
        _, records, _ = self.inventory()
        with patch.object(guest, 'manager', side_effect=[original, replacement]), \
                patch.object(guest, 'collector_diagnostic', return_value={'runtime.json': {'state': 'idle', 'cycle': 1}}), \
                patch.object(guest, 'read_receipt', return_value=records[0]) as read, \
                patch.object(guest, 'request', return_value={'ok': True, 'committed_count': 2, 'process_id': 777}), \
                patch.object(guest, 'command') as command:
            with self.assertRaisesRegex(guest.CollectorRestartError, guest.COLLECTOR_RESTART) as caught:
                continuity.reproduce()
            read.assert_called_once_with(guest.PRIVATE / 'receipt-0002.json')
            command.assert_called_once_with(['systemctl', 'kill', '--kill-who=main', '--signal=KILL', guest.COLLECTOR_UNIT])
        logs = {guest.COLLECTOR_UNIT: {'recent_log': 'Main process exited, code=killed, status=9/KILL'}}
        output = io.StringIO()
        with redirect_stderr(output), patch.object(guest, 'diagnostics', return_value=logs):
            continuity.report(caught.exception)
        line = output.getvalue().strip()
        self.assertLessEqual(len(line.encode()), guest.MAX_RESTART_DIAGNOSTIC)
        self.assertTrue(line.startswith(guest.RESTART_DIAGNOSTIC_PREFIX))
        report = json.loads(line.removeprefix(guest.RESTART_DIAGNOSTIC_PREFIX))
        self.assertTrue(report['injected'])
        self.assertEqual(report['current']['MainPID'], 124)
        self.assertEqual(report['current']['NRestarts'], 1)
        self.assertEqual(report['first_receipt']['delivery_process_id'], report['initial']['MainPID'])
        self.assertEqual(report['last_monitor_status']['committed_count'], 2)
        self.assertEqual(report['bounded_unit_diagnostics'], logs)

    def test_diagnostic_and_cleanup_failures_preserve_original_stage(self):
        failure = guest.CollectorRestartError('collector_identity_verification', current=self.collector_manager(124, 1))
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data, report = root / 'data', root / 'data' / 'report'
            lab = MagicMock()
            lab.cleanup.side_effect = RuntimeError('cleanup failure')
            def diagnostic(error):
                self.assertIs(error, failure)
                self.assertEqual(lab.cleanup.call_count, 0)
                raise OSError('diagnostic failure')
            with redirect_stderr(output), patch.multiple(guest, DATA=data, REPORT=report, PUBLISH=report / 'publish', RUNTIME=root / 'run'), \
                    patch.object(guest, 'guard'), patch.object(guest.reboot, 'boot_info'), patch.object(guest.reboot.base, 'preflight'), \
                    patch.object(guest.automatic.monitoring, 'MonitoringLab', return_value=lab), \
                    patch.object(guest, 'unit_path', return_value=root / 'absent'), \
                    patch.object(guest.CollectorContinuity, 'report', side_effect=diagnostic), \
                    patch.object(guest, 'run_exercise', side_effect=failure):
                with self.assertRaises(guest.CollectorRestartError) as caught:
                    guest.exercise('token')
        self.assertIs(caught.exception, failure)
        lab.cleanup.assert_called_once()
        self.assertIn(guest.COLLECTOR_RESTART, output.getvalue())

    def test_injection_flag_is_rejected_for_worker_and_cleanup(self):
        for stage in ('worker', 'cleanup'):
            with patch.object(guest.sys, 'argv', ['guest', stage, '--inject-collector-restart']), \
                    patch.object(guest, 'worker') as worker, patch.object(guest, 'cleanup') as cleanup, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    guest.main()
            self.assertEqual(caught.exception.code, 2)
            worker.assert_not_called()
            cleanup.assert_not_called()


if __name__ == '__main__':
    unittest.main()

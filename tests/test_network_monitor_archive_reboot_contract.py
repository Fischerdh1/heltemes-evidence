"""Synthetic complete-artifact contract tests; these are not VM or packet evidence."""
import copy
import hashlib
import json
import unittest

from scripts import network_monitor_archive_reboot_vm as host


def fingerprint(raw):
    return hashlib.sha256(raw).hexdigest()


def contract_fixture(*, missing=False, missing_error='freshness_deadline_exceeded'):
    """Build small invented artifacts solely to exercise the host's whole contract."""
    boot_ids = {'before': '11111111-1111-4111-8111-111111111111',
                'after': '22222222-2222-4222-8222-222222222222'}
    source = {'source_sha256': {name: 'a' * 64 for name in host.SOURCE_FILES}}
    hashes = {name: source['source_sha256'][name] for name in host.GUEST_SOURCE_FILES}
    critical, incident = host.CRITICAL, host.CRITICAL + '#1'
    rows, receipts, events, previous = [], [], [], '0' * 64

    def append(request_id, observation, evaluation, *, kind='observation', resolved=False):
        nonlocal previous
        sequence = len(rows) + 1
        row_events = ([{'key': critical, 'action': 'resolved', 'alert_id': incident, 'sequence': sequence}]
                      if resolved else [])
        payload = {'sequence': sequence, 'request_id': request_id, 'request': {'kind': kind, 'observation': observation},
                   'sample': {**copy.deepcopy(observation), 'sequence': sequence}, 'evaluation': evaluation,
                   'events': row_events, 'previous_digest': previous}
        row = {**payload, 'row_digest': fingerprint(host.canonical(payload))}
        rows.append(row); events.extend(row_events); previous = row['row_digest']
        return row

    def marker(number, *, gap=False):
        phase = 'collector_missing' if gap else 'monitor_restart'
        observation = {'phase': phase, 'ruleset': None, 'probes': [],
                       'collection_error': missing_error if gap else 'monitor_restarted'}
        append(('freshness-gap-' if gap else '_restart_') + str(number) * 32,
               observation, {'status': 'unknown', 'active_alert_keys': ['telemetry_gap:collector', critical]},
               kind='observation' if gap else 'restart')

    marker(1)
    for cycle in range(1, 401):
        if cycle == 271:
            marker(2)
            if missing:
                marker(2, gap=True)
        phase = 'before' if cycle <= 270 else 'after'
        local = cycle if phase == 'before' else cycle - 270
        instance = ('a' if phase == 'before' else 'b') * 32
        request_id = f'archive_reboot_{instance}_{cycle}'
        full = local == 3 or (local > 2 and cycle % 16 == 0)
        probes, port = [], 42000 + 6 * (cycle - 1)
        if full:
            for source_zone, target, target_port in (('user', 'app', 8080), ('user', 'app', 9090), ('management', 'app', 9090)):
                probes.append({'from': source_zone, 'to': target, 'port': target_port, 'source_port': port,
                               'destination_health': None})
                port += 1
        observation = {'phase': request_id, 'ruleset': {'nftables': []}, 'collection_error': None, 'probes': probes}
        evaluation = {'status': ('healthy' if full and (cycle == 3 or cycle >= 273) else 'unknown'),
                      'active_alert_keys': [critical] if 16 <= cycle < 273 else []}
        row = append(request_id, observation, evaluation, resolved=cycle == 273)
        receipts.append({'instance_id': instance, 'process_id': 50 if phase == 'before' else 60,
                         'delivery_process_id': 50 if phase == 'before' else 60,
                         'boot_id': boot_ids[phase], 'delivery_boot_id': boot_ids[phase], 'cycle': cycle,
                         'process_cycle': local, 'request': {'command': 'observe', 'request_id': request_id,
                                                           'observation': copy.deepcopy(observation)},
                         'committed_sequence': row['sequence'], 'evaluation': copy.deepcopy(evaluation),
                         'duplicate_acknowledgement': False, 'delivery_attempts': 1, 'transport_failures': [],
                         'started_monotonic': float(local), 'completed_monotonic': local + 0.1})

    identity = {'database_id': 'c' * 32, 'format': 'heltemes-monitor-archive-journal', 'version': 1,
                'segment_rows': 128, 'max_rows': 2048, 'max_segments': 16}
    files = {name: b'synthetic contract fixture, not a capture' for name in host.CAPTURE_FILES}
    files.update({name: b'synthetic contract fixture' for name in host.COMMON_FILES})
    descriptors, proofs = [], []
    for index, name in enumerate(host.SEGMENT_FILES, 1):
        prefix = rows[(index - 1) * 128:index * 128]
        segment = {'format': 'heltemes-monitor-archive-journal-segment', 'version': 1,
                   'database_id': identity['database_id'], 'segment_index': index,
                   'first_sequence': prefix[0]['sequence'], 'last_sequence': prefix[-1]['sequence'],
                   'previous_digest': prefix[0]['previous_digest'], 'last_digest': prefix[-1]['row_digest'], 'rows': prefix}
        raw = host.canonical(segment) + b'\n'; files[name] = raw
        descriptors.append({'segment_index': index, 'first_sequence': prefix[0]['sequence'],
                            'last_sequence': prefix[-1]['sequence'], 'row_count': 128, 'byte_count': len(raw),
                            'file_digest': fingerprint(raw), 'last_digest': prefix[-1]['row_digest']})
        proofs.append({'public_name': name, 'name': f'segment-{index:06d}.json', 'bytes': len(raw),
                       'sha256': fingerprint(raw), 'mode': 0o600, 'uid': 0, 'nlink': 1})

    def status(sequence, *, startup=False):
        return {'process_id': 100 if sequence <= 271 else 200, 'committed_count': sequence,
                'head_digest': rows[sequence - 1]['row_digest'],
                'current_evaluation': copy.deepcopy(rows[sequence - 1]['evaluation']),
                'alerts': [{'key': critical, 'id': incident, 'state': 'open'}] if sequence < receipts[272]['committed_sequence'] else [],
                'freshness': {'last_accepted_request_id': None if startup else rows[sequence - 1]['request_id']},
                'archives': {'sealed_segments': sequence // 128, 'archived_rows': sequence // 128 * 128,
                             'active_rows': sequence % 128, 'capacity_remaining': 2048 - sequence, 'persistence_error': None}}

    reports, histories = {}, {}
    for phase, count, segments in (('before', 271, 2), ('after', len(rows), 3)):
        history = {'history_complete': True, 'identity': identity, 'approved_policy': {'synthetic_fixture': True},
                   'rows': rows[:count], 'archive_descriptors': descriptors[:segments],
                   'events': [event for event in events if event['sequence'] <= count]}
        name = phase.upper() + '-HISTORY.json'; raw = host.canonical(history) + b'\n'; files[name] = raw
        report = {'format': 'heltemes-monitor-archive-reboot-guest', 'version': 1, 'ok': True, 'stage': phase,
                  'source_sha256': hashes, 'boot': {'boot_id': boot_ids[phase]},
                  'history_file': {'name': name, 'bytes': len(raw), 'sha256': fingerprint(raw)},
                  'journal_export_method': 'stopped_verified_journal',
                  'monitor_stopped_for_export': {'ActiveState': 'inactive', 'MainPID': 0, 'UnitFileState': 'enabled'},
                  'final_status': status(count), 'archive_files': proofs[:segments],
                  'capture_sha256': {name: fingerprint(files[name]) for name in host.CAPTURE_FILES if name.startswith(phase + '-')},
                  'critical_incident_id': incident, 'manager': {'InvocationID': phase},
                  'collector_receipts': receipts[:270] if phase == 'before' else receipts[270:]}
        reports[phase], histories[phase] = report, history
    reports['before']['no_pending_before_reboot'] = True
    startup_count = 273 if missing else 272
    startup_status = status(startup_count, startup=True)
    reports['after'].update({'automatic_start': {'no_manual_service_start': True, 'status': startup_status,
        'manager': {'ActiveState': 'active', 'UnitFileState': 'enabled', 'MainPID': 200, 'InvocationID': 'after'},
        'readonly_history': {'identity': identity, 'approved_policy': histories['before']['approved_policy'],
                             'segments': descriptors[:2], 'archived_sequence': 256, 'archived_digest': rows[255]['row_digest'],
                             'head_sequence': startup_count, 'head_digest': rows[startup_count - 1]['row_digest'],
                             'rows': rows[256:startup_count]}},
        'network_missing_before_rebuild': True, 'preboot_prefix_preserved': True,
        'first_rule_only_receipts': receipts[270:272], 'network_cleanup': {'ok': True},
        'archived_duplicate': {'request': receipts[0]['request'], 'before_status': copy.deepcopy(startup_status),
                              'after_status': copy.deepcopy(startup_status),
                              'result': {'ok': True, 'duplicate': True, 'committed_sequence': receipts[0]['committed_sequence'],
                                         'evaluation': receipts[0]['evaluation']}}})
    for phase, report in reports.items():
        files[phase.upper() + '.json'] = host.canonical(report) + b'\n'
    held = {name: files[name] for name in host.PREBOOT_FILES}
    reboot = {phase: {'boot_id': boot} for phase, boot in boot_ids.items()}
    return held, files, source, reboot


class ArchiveRebootContractTests(unittest.TestCase):
    def test_full_contract_accepts_both_explicit_startup_gap_shapes(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                before, after = host.validate_guest(*contract_fixture(missing=missing))
                self.assertEqual(before['final_status']['committed_count'], 271)
                self.assertEqual(after['final_status']['committed_count'], 403 if missing else 402)

    def test_self_consistent_hashes_do_not_authorize_an_unexplained_gap(self):
        with self.assertRaisesRegex(RuntimeError, 'missing-data row'):
            host.validate_guest(*contract_fixture(missing=True, missing_error='fabricated_observation'))

    def test_after_report_cannot_lie_about_receipts_startup_or_resolution(self):
        cases = (
            ('delivery_boot', lambda a: a['collector_receipts'][0].update(delivery_boot_id='wrong')),
            ('local_cycle', lambda a: a['collector_receipts'][0].update(process_cycle=271)),
            ('global_cycle', lambda a: a['collector_receipts'][0].update(cycle=270)),
            ('reused_port', lambda a: a['collector_receipts'][2]['request']['observation']['probes'][0].update(source_port=42000)),
            ('startup_health', lambda a: a['automatic_start']['status']['current_evaluation'].update(status='healthy')),
            ('writer_running', lambda a: a['monitor_stopped_for_export'].update(MainPID=200)),
            ('snapshot_rollback', lambda a: a['automatic_start']['readonly_history'].update(archived_digest='0' * 64)),
            ('retry_new_head', lambda a: a['archived_duplicate']['after_status'].update(head_digest='0' * 64)),
            ('lost_incident', lambda a: a['first_rule_only_receipts'][0]['evaluation'].update(active_alert_keys=[])),
        )
        for label, mutate in cases:
            held, files, source, reboot = contract_fixture()
            report = json.loads(files['AFTER.json']); mutate(report)
            files['AFTER.json'] = host.canonical(report) + b'\n'
            with self.subTest(case=label), self.assertRaises(RuntimeError):
                host.validate_guest(held, files, source, reboot)


if __name__ == '__main__':
    unittest.main()

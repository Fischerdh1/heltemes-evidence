"""Failed or skipped prerequisites must block reviewer packaging."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


CI_WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml'


class MonitorCIGateTests(unittest.TestCase):
    def test_workflow_guard_rejects_unsuccessful_or_missing_vm_job(self):
        workflow = CI_WORKFLOW.read_text()
        reviewer = workflow.split('\n  reviewer:\n', 1)[1]
        names = (
            'python', 'terraform', 'network_lab', 'monitor_reboot', 'monitor_powercut', 'monitor_automatic',
            'monitor_archive', 'monitor_archive_reboot', 'monitor_archive_powercut', 'monitor_archive_retry',
            'clean_restore', 'key_rotation_restore', 'monitor_boot', 'monitor_boot_powercut',
        )
        self.assertIn('    if: ${{ always() }}\n', reviewer)
        self.assertIn(f"    needs: [{', '.join(names)}]\n", reviewer)
        self.assertIn('PREREQUISITE_RESULTS: ${{ toJSON(needs) }}', reviewer)
        guard = reviewer.split("          python3 - <<'PY'\n", 1)[1].split('\n          PY', 1)[0]
        script = '\n'.join(line[10:] for line in guard.splitlines())
        passing = {name: {'result': 'success'} for name in names}
        cases = [(passing, True), ({**passing, 'unexpected': {'result': 'success'}}, False)]
        for prerequisite in names:
            for state in ('failure', 'skipped', 'cancelled', 'in_progress', None):
                cases.append(({**passing, prerequisite: {'result': state}}, False))
            cases.append(({key: value for key, value in passing.items() if key != prerequisite}, False))
        for results, accepted in cases:
            with self.subTest(results=results):
                process = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script],
                    env={**os.environ, 'PREREQUISITE_RESULTS': json.dumps(results)},
                    capture_output=True, timeout=10)
                self.assertEqual(process.returncode == 0, accepted, process.stderr.decode())

    def test_clean_restore_job_runs_the_vm_and_uploads_only_public_evidence(self):
        workflow = CI_WORKFLOW.read_text()
        job = workflow.split('\n  clean_restore:\n', 1)[1].split('\n  monitor_archive_retry:\n', 1)[0]
        self.assertIn('    needs: [python]\n', job)
        self.assertIn('    runs-on: ubuntu-24.04\n', job)
        self.assertIn('    timeout-minutes: 18\n', job)
        self.assertIn('REVIEWER_PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}', job)
        self.assertIn(
            'python3 -I -S -B scripts/clean_restore_vm.py --output work/clean-machine-restore',
            job,
        )
        self.assertNotIn('continue-on-error', job)
        self.assertIn('\npermissions:\n  contents: read\n\njobs:\n', workflow)
        self.assertIn('          persist-credentials: false\n', job)
        self.assertNotIn('secrets.', job)
        self.assertNotIn('permissions:', job)
        actions = [line.split('uses: ', 1)[1] for line in job.splitlines() if 'uses: ' in line]
        self.assertEqual(len(actions), 2)
        self.assertRegex(actions[0], r'^actions/checkout@[0-9a-f]{40}(?:\s|$)')
        self.assertRegex(actions[1], r'^actions/upload-artifact@[0-9a-f]{40}(?:\s|$)')
        self.assertIn(
            'apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils openssh-client curl\n',
            job,
        )
        artifact = job.split('          path: |\n', 1)[1].split('          if-no-files-found: error\n', 1)[0]
        self.assertCountEqual(
            [line.strip() for line in artifact.splitlines()],
            [
                'work/clean-machine-restore/CLEAN-RESTORE.json',
                'work/clean-machine-restore/MANIFEST.json',
            ],
        )

    def test_key_rotation_restore_job_uploads_only_reports(self):
        workflow = CI_WORKFLOW.read_text()
        job = workflow.split('\n  key_rotation_restore:\n', 1)[1].split('\n  clean_restore:\n', 1)[0]
        self.assertIn('    runs-on: ubuntu-24.04\n', job)
        self.assertIn('    timeout-minutes: 5\n', job)
        self.assertIn('          persist-credentials: false\n', job)
        self.assertIn('REVIEWER_PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}', job)
        self.assertIn(
            'python3 -I -S -B scripts/key_rotation_restore_drill.py --output work/key-rotation-restore',
            job,
        )
        self.assertNotIn('continue-on-error', job)
        self.assertNotIn('secrets.', job)
        self.assertNotIn('permissions:', job)
        self.assertIn('          retention-days: 30\n', job)
        actions = [line.split('uses: ', 1)[1] for line in job.splitlines() if 'uses: ' in line]
        self.assertEqual(len(actions), 2)
        self.assertRegex(actions[0], r'^actions/checkout@[0-9a-f]{40}(?:\s|$)')
        self.assertRegex(actions[1], r'^actions/upload-artifact@[0-9a-f]{40}(?:\s|$)')
        artifact = job.split('          path: |\n', 1)[1].split('          if-no-files-found: error\n', 1)[0]
        self.assertCountEqual(
            [line.strip() for line in artifact.splitlines()],
            ['work/key-rotation-restore/REPORT.json', 'work/key-rotation-restore/MANIFEST.json'],
        )

    def test_automatic_boot_jobs_run_and_retain_only_bounded_evidence(self):
        workflow = CI_WORKFLOW.read_text()
        cases = (
            ('monitor_boot', 'monitor_boot_powercut', 'network-monitor-boot',
             'network_monitor_boot_vm.py', ('NORMAL.json', 'FAILED.json')),
            ('monitor_boot_powercut', 'key_rotation_restore', 'network-monitor-boot-powercut',
             'network_monitor_boot_powercut_vm.py', ()),
        )
        for name, following, output, script, extra in cases:
            with self.subTest(job=name):
                job = workflow.split(f'\n  {name}:\n', 1)[1].split(f'\n  {following}:\n', 1)[0]
                self.assertIn('    needs: [python]\n', job)
                self.assertIn('    runs-on: ubuntu-24.04\n', job)
                self.assertIn('    timeout-minutes: 23\n', job)
                self.assertNotIn('\n    if:', job)
                self.assertNotIn('continue-on-error', job)
                self.assertNotIn('secrets.', job)
                self.assertIn('          persist-credentials: false\n', job)
                self.assertIn('REVIEWER_PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}', job)
                self.assertIn(f'python3 -I -S -B scripts/{script} --output work/{output}', job)
                actions = [line.split('uses: ', 1)[1] for line in job.splitlines() if 'uses: ' in line]
                self.assertEqual(len(actions), 3)
                self.assertRegex(actions[0], r'^actions/checkout@[0-9a-f]{40}(?:\s|$)')
                for action in actions[1:]:
                    self.assertRegex(action, r'^actions/upload-artifact@[0-9a-f]{40}(?:\s|$)')
                success, failure = job.split('        if: failure()\n', 1)
                artifact = success.split('          path: |\n', 1)[1]
                members = artifact.split('          if-no-files-found: error\n', 1)[0].splitlines()
                self.assertCountEqual(
                    [line.strip() for line in members],
                    [f'work/{output}/publish/{file}' for file in
                     ('REPORT.json', 'VM.json', 'BEFORE.json', *extra, 'RECOVERED.json', 'MANIFEST.json')],
                )
                self.assertIn('retention-days: 30', success)
                self.assertEqual([line.strip() for line in failure.splitlines() if 'path:' in line],
                                 [f'path: work/{output}/staging/FAILURE.json'])
                self.assertIn('retention-days: 7', failure)

    def test_archive_retry_job_runs_the_vm_and_uploads_only_public_evidence(self):
        workflow = CI_WORKFLOW.read_text()
        job = workflow.split('\n  monitor_archive_retry:\n', 1)[1].split('\n  reviewer:\n', 1)[0]
        self.assertIn('    needs: [python]\n', job)
        self.assertIn('    timeout-minutes: 15\n', job)
        self.assertIn('REVIEWER_PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}', job)
        self.assertIn(
            'python3 -I -S -B scripts/archive_reboot_retry_drill_vm.py --output work/archive-reboot-retry-drill',
            job,
        )
        self.assertNotIn('continue-on-error', job)
        artifact = job.split('          path: |\n', 1)[1].split('          if-no-files-found: error\n', 1)[0]
        self.assertCountEqual(
            [line.strip() for line in artifact.splitlines()],
            [
                f'work/archive-reboot-retry-drill/publish/{name}'
                for name in ('REPORT.json', 'DRILL.json', 'VM.json', 'MANIFEST.json')
            ],
        )


if __name__ == '__main__':
    unittest.main()

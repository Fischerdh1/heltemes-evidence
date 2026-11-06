"""A failed or skipped VM exercise must never produce reviewer acceptance."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


class MonitorCIGateTests(unittest.TestCase):
    def test_workflow_guard_rejects_unsuccessful_or_missing_vm_job(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml').read_text()
        reviewer = workflow.split('\n  reviewer:\n', 1)[1]
        self.assertIn('    if: ${{ always() }}\n', reviewer)
        self.assertIn('    needs: [python, terraform, network_lab, monitor_reboot, monitor_powercut, monitor_automatic, monitor_archive, monitor_archive_reboot]\n', reviewer)
        self.assertIn('PREREQUISITE_RESULTS: ${{ toJSON(needs) }}', reviewer)
        guard = reviewer.split("          python3 - <<'PY'\n", 1)[1].split('\n          PY', 1)[0]
        script = '\n'.join(line[10:] for line in guard.splitlines())
        names = ('python', 'terraform', 'network_lab', 'monitor_reboot', 'monitor_powercut', 'monitor_automatic', 'monitor_archive', 'monitor_archive_reboot')
        passing = {name: {'result': 'success'} for name in names}
        cases = [(passing, True)]
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


if __name__ == '__main__':
    unittest.main()

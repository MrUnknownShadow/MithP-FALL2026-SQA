'''
Tests for the forensics logging added to 10 scanner methods (COMP 5710/6710 SQA).
Each method must log an `enter` and an `exit` event on success, and an
`enter` and an `error` event when it raises.
'''
import json
import os
import tempfile
import unittest

_LOG = os.path.join(tempfile.mkdtemp(), 'forensics_test.log')
os.environ['FORENSICS_LOG'] = _LOG        # must be set before forensics is imported

import scanner  # noqa: E402

INSTRUMENTED = ['scanForOverPrivileges', 'scanSingleManifest', 'scanForMissingSecurityContext',
                'scanForDefaultNamespace', 'scanForResourceLimits', 'scanForRollingUpdates',
                'scanForMissingNetworkPolicy', 'scanForTruePID', 'scanForTrueIPC', 'scanDockerSock']
CLEAN_FILE = 'TEST_ARTIFACTS/empty.yml'
MISSING    = 'TEST_ARTIFACTS/does_not_exist.yaml'


def events():
    with open(_LOG, encoding='utf-8') as handle:
        return [json.loads(line) for line in handle if line.strip()]


class TestForensics(unittest.TestCase):

    def test_success_path_logs_enter_and_exit(self):
        for name in INSTRUMENTED:
            with self.subTest(method=name):
                before = len(events())
                getattr(scanner, name)(CLEAN_FILE)
                new = events()[before:]
                self.assertEqual(['enter', 'exit'], [e['event'] for e in new])
                self.assertTrue(all(e['func'] == name for e in new))

    def test_enter_records_argument_and_file_hash(self):
        scanner.scanForTruePID(CLEAN_FILE)
        enter = [e for e in events() if e['event'] == 'enter' and e['func'] == 'scanForTruePID'][-1]
        self.assertIn(CLEAN_FILE, enter['args']['path_script'])
        self.assertEqual(64, len(enter['file_sha256']['path_script']))

    def test_error_path_logs_exception_and_reraises(self):
        for name in INSTRUMENTED:
            with self.subTest(method=name):
                before = len(events())
                with self.assertRaises(FileNotFoundError):
                    getattr(scanner, name)(MISSING)
                new = events()[before:]
                self.assertEqual(['enter', 'error'], [e['event'] for e in new])
                self.assertEqual('FileNotFoundError', new[-1]['exc_type'])
                self.assertIn('Traceback', new[-1]['traceback'])


if __name__ == '__main__':
    unittest.main()

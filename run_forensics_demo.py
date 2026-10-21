'''
Runs the 10 forensics-instrumented scanner methods over every YAML file in
TEST_ARTIFACTS/ and prints a summary of what the forensics log recorded.
Exceptions are caught here so one bad file does not stop the run; each one is
already recorded in the log as an `error` event with its traceback.

Usage: python run_forensics_demo.py [artifacts_dir]
Log:   forensics.log (override with FORENSICS_LOG)
'''
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)

import forensics   # noqa: E402
import scanner     # noqa: E402

METHODS = ['scanForOverPrivileges', 'scanSingleManifest', 'scanForMissingSecurityContext',
           'scanForDefaultNamespace', 'scanForResourceLimits', 'scanForRollingUpdates',
           'scanForMissingNetworkPolicy', 'scanForTruePID', 'scanForTrueIPC', 'scanDockerSock']


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else 'TEST_ARTIFACTS'
    open(forensics.LOG_PATH, 'w').close()          # start from a clean log
    files = scanner.getYAMLFiles(folder)
    for path in sorted(files):
        for name in METHODS:
            try:
                getattr(scanner, name)(path)
            except Exception:
                pass                                # already recorded as an error event
    counts, errors = collections.Counter(), collections.Counter()
    with open(forensics.LOG_PATH, encoding='utf-8') as handle:
        for line in handle:
            event = json.loads(line)
            counts[event['event']] += 1
            if event['event'] == 'error':
                errors[(event['func'], event['exc_type'], event['exc_msg'][:60])] += 1
    print('files scanned : %d' % len(files))
    print('methods       : %d' % len(METHODS))
    print('log events    : enter=%d exit=%d error=%d' % (counts['enter'], counts['exit'], counts['error']))
    print('log file      : %s' % forensics.LOG_PATH)
    for (func, exc_type, msg), n in errors.most_common():
        print('  error x%-3d %s -> %s: %s' % (n, func, exc_type, msg))


if __name__ == '__main__':
    main()

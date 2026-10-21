'''
fuzz.py - automatic fuzzing of 10 SLI-KUBE Python methods (COMP 5710/6710 SQA).

Each target is called many times with randomly generated inputs (wrong types,
empty values, huge values, odd unicode, deeply nested structures, binary files).
Every unhandled exception, hang, or RecursionError is recorded once per unique
(method, exception type, message) together with the input that triggered it.

Usage:
    python fuzz.py                      # defaults: seed 5710, 1000 iterations per method
    python fuzz.py --iters 2000 --seed 7
    python fuzz.py --strict             # exit 1 when any bug is found (default exit 0)

Outputs (folder fuzz_results/ by default):
    fuzz_report.json   machine readable findings
    fuzz_report.md     human readable findings with reproducers
GitHub Actions runs this file on every push and uploads both reports.
'''
import argparse
import json
import math
import os
import random
import signal
import string
import sys
import tempfile
import time
import traceback
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)
# keep fuzz-induced forensics events separate from normal runs
os.environ.setdefault('FORENSICS_LOG', os.path.join(HERE, 'fuzz_results', 'fuzz_forensics.log'))
os.makedirs(os.path.join(HERE, 'fuzz_results'), exist_ok=True)

import parser as kube_parser   # project module (named parser.py)
import scanner

CALL_TIMEOUT_SECONDS = 3
PREVIEW_LIMIT        = 200

# ----------------------------------------------------------------------------
# random input generators
# ----------------------------------------------------------------------------
_UNICODE_BITS = ['é', '中', '🙂', '‮', '\x00', '\t', '\n', '\r\n', '  ', '\\', '"', "'"]
_KEYWORDS     = ['apiVersion', 'kind', 'spec', 'containers', 'securityContext', 'privileged',
                 'user', 'password', 'passwd', 'pwd', 'admin_pass', 'crt', 'key', 'default',
                 'github/workflows/', '.github/', '.travis.yml', 'helm', 'values', 'chart',
                 '-----BEGIN CERTIFICATE-----', 'hiera', 'Secret', 'ConfigMap', 'Deployment']


class Opaque(object):
    '''arbitrary object with a stable repr so reports do not contain memory addresses'''
    def __repr__(self):
        return '<Opaque>'


def rand_str(rng):
    roll = rng.random()
    if roll < 0.15:
        return ''
    if roll < 0.40:
        return rng.choice(_KEYWORDS)
    if roll < 0.50:
        return rng.choice(_KEYWORDS) + ''.join(rng.choice(string.printable) for _ in range(rng.randint(0, 8)))
    if roll < 0.55:
        return 'a' * rng.randint(5000, 20000)
    pool = string.ascii_letters + string.digits + string.punctuation + ' ' + ''.join(_UNICODE_BITS)
    return ''.join(rng.choice(pool) for _ in range(rng.randint(1, 40)))


def rand_scalar(rng):
    roll = rng.random()
    if roll < 0.45:
        return rand_str(rng)
    if roll < 0.55:
        return rng.randint(-2**70, 2**70)
    if roll < 0.62:
        return rng.choice([0.0, -0.0, 1.5, math.inf, -math.inf, math.nan])
    if roll < 0.72:
        return rng.choice([True, False])
    if roll < 0.82:
        return None
    if roll < 0.90:
        return bytes(rng.randrange(256) for _ in range(rng.randint(0, 12)))
    return rng.choice([(), (1, 2), frozenset([1]), Opaque()])


def rand_key(rng):
    return rand_str(rng) if rng.random() < 0.7 else rng.choice([0, 7, -1, 2.5, True, None, (1, 2), b'k'])


def rand_value(rng, depth=0):
    if depth >= 3 or rng.random() < 0.45:
        return rand_scalar(rng)
    if rng.random() < 0.5:
        return [rand_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {rand_key(rng): rand_value(rng, depth + 1) for _ in range(rng.randint(0, 4))}


def rand_dict(rng):
    return {rand_key(rng): rand_value(rng) for _ in range(rng.randint(0, 6))}


def deep_nested(rng, depth=None):
    '''deeply nested dict/list structure to provoke RecursionError'''
    depth = depth or rng.choice([500, 1200, 3000])
    mode = rng.choice(['dict', 'list', 'mixed'])
    node = rng.choice(['leaf', 1, None])
    for _ in range(depth):
        if mode == 'dict' or (mode == 'mixed' and rng.random() < 0.5):
            node = {'k': node}
        else:
            node = [node]
    return node


def maybe_deep(rng, value):
    return deep_nested(rng) if rng.random() < 0.02 else value


def rand_any(rng):
    return rand_value(rng) if rng.random() < 0.5 else rand_str(rng)


def make_text_file(rng, directory):
    '''random file for the file-reading target: binary junk or YAML-ish lines'''
    path = os.path.join(directory, 'fuzz_%d.yaml' % rng.randrange(10**9))
    if rng.random() < 0.3:
        data = bytes(rng.randrange(256) for _ in range(rng.randint(0, 200)))
    else:
        lines = []
        for _ in range(rng.randint(0, 15)):
            lines.append(rng.choice(['#c', '# comment', '', '---', 'key: value', '- item', '  nested: 1', rand_str(rng)]))
        data = '\n'.join(lines).encode('utf-8', errors='replace')
    with open(path, 'wb') as handle:
        handle.write(data)
    return path


# ----------------------------------------------------------------------------
# the 10 fuzz targets: (label, callable, argument factory)
# ----------------------------------------------------------------------------
def targets(tmpdir):
    return OrderedDict([
        ('parser.checkIfWeirdYAML',
         (kube_parser.checkIfWeirdYAML, lambda r: (rand_any(r),))),
        ('parser.keyMiner',
         (kube_parser.keyMiner, lambda r: (maybe_deep(r, rand_value(r)), rand_scalar(r)))),
        ('parser.getKeyRecursively',
         (kube_parser.getKeyRecursively, lambda r: (maybe_deep(r, rand_dict(r)), [], r.choice([0, 0, 0, -1, 5])))),
        ('parser.getValsFromKey',
         (kube_parser.getValsFromKey, lambda r: (maybe_deep(r, rand_dict(r)), rand_scalar(r), []))),
        ('parser.getSingleDict4MultiDocs',
         (kube_parser.getSingleDict4MultiDocs, lambda r: ([rand_value(r) for _ in range(r.randint(0, 4))],))),
        ('parser.checkIfValidHelm',
         (kube_parser.checkIfValidHelm, lambda r: (rand_any(r),))),
        ('parser.find_json_path_keys',
         (kube_parser.find_json_path_keys, lambda r: (maybe_deep(r, rand_value(r)),))),
        ('scanner.checkIfValidSecret',
         (scanner.checkIfValidSecret, lambda r: (rand_any(r),))),
        ('scanner.scanUserName',
         (scanner.scanUserName, lambda r: (rand_scalar(r), [rand_scalar(r) for _ in range(r.randint(0, 4))] if r.random() < 0.9 else rand_scalar(r)))),
        ('parser.count_initial_comment_line',
         (kube_parser.count_initial_comment_line, lambda r: (make_text_file(r, tmpdir),))),
    ])


# ----------------------------------------------------------------------------
# execution engine
# ----------------------------------------------------------------------------
class CallTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise CallTimeout('call exceeded %d seconds' % CALL_TIMEOUT_SECONDS)


def preview(obj):
    try:
        text = repr(obj)
    except RecursionError:
        text = '<repr failed: structure too deep>'
    except Exception as exc:
        text = '<unrepresentable %s>' % type(exc).__name__
    return text if len(text) <= PREVIEW_LIMIT else text[:PREVIEW_LIMIT] + '...<%d chars>' % len(text)


def innermost_frame(exc):
    frames = traceback.extract_tb(exc.__traceback__)
    mine = [f for f in frames if os.path.abspath(f.filename).startswith(HERE) and not f.filename.endswith('fuzz.py')]
    # a RecursionError is raised at whatever depth the limit is hit, so report the entry frame to keep findings stable
    f = (mine or frames)[0 if isinstance(exc, RecursionError) else -1]
    if isinstance(exc, RecursionError):
        return '%s in %s' % (os.path.basename(f.filename), f.name)
    return '%s:%d in %s' % (os.path.basename(f.filename), f.lineno, f.name)


def run_target(label, func, factory, iters, rng):
    findings = OrderedDict()
    calls = crashes = 0
    use_alarm = hasattr(signal, 'SIGALRM')
    for _ in range(iters):
        args = factory(rng)
        shown = preview(args)
        calls += 1
        if use_alarm:
            signal.signal(signal.SIGALRM, _alarm_handler)
            signal.alarm(CALL_TIMEOUT_SECONDS)
        try:
            func(*args)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            crashes += 1
            where = innermost_frame(exc)
            key = (type(exc).__name__, where)          # one finding per root cause (type + code location)
            if key not in findings:
                findings[key] = {'method': label, 'exception': type(exc).__name__,
                                 'message': str(exc).splitlines()[0][:200] if str(exc) else '',
                                 'location': where, 'first_input': shown, 'occurrences': 0}
            findings[key]['occurrences'] += 1
        finally:
            if use_alarm:
                signal.alarm(0)
    return calls, crashes, list(findings.values())


def write_reports(out_dir, seed, iters, summary, all_findings):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, 'fuzz_report.json'), 'w', encoding='utf-8') as handle:
        json.dump({'seed': seed, 'iterations_per_method': iters, 'summary': summary, 'findings': all_findings}, handle, indent=2)
    lines = ['# Fuzzing report', '', 'seed=%d, iterations per method=%d' % (seed, iters), '',
             '| Method | Calls | Crashing calls | Unique bugs |', '|---|---|---|---|']
    for label, s in summary.items():
        lines.append('| %s | %d | %d | %d |' % (label, s['calls'], s['crashing_calls'], s['unique_bugs']))
    lines += ['', '## Findings', '']
    for i, f in enumerate(all_findings, 1):
        lines += ['### BUG-%02d  %s -> %s' % (i, f['method'], f['exception']),
                  '- message: `%s`' % f['message'].replace('`', "'"),
                  '- raised at: `%s`' % f['location'],
                  '- occurrences: %d' % f['occurrences'],
                  '- first input: `%s`' % f['first_input'].replace('`', "'").replace('\n', '\\n'), '']
    with open(os.path.join(out_dir, 'fuzz_report.md'), 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(lines))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--iters', type=int, default=int(os.environ.get('FUZZ_ITERS', 1000)))
    ap.add_argument('--seed', type=int, default=int(os.environ.get('FUZZ_SEED', 5710)))
    ap.add_argument('--out', default=os.path.join(HERE, 'fuzz_results'))
    ap.add_argument('--strict', action='store_true', help='exit 1 if any bug is found')
    opts = ap.parse_args()

    started = time.time()
    summary, all_findings = OrderedDict(), []
    sys.setrecursionlimit(1000)
    with tempfile.TemporaryDirectory() as tmpdir:
        for label, (func, factory) in targets(tmpdir).items():
            rng = random.Random('%s:%s' % (opts.seed, label))
            calls, crashes, found = run_target(label, func, factory, opts.iters, rng)
            summary[label] = {'calls': calls, 'crashing_calls': crashes, 'unique_bugs': len(found)}
            all_findings.extend(found)
            print('%-38s calls=%-5d crashing=%-5d unique_bugs=%d' % (label, calls, crashes, len(found)))
    write_reports(opts.out, opts.seed, opts.iters, summary, all_findings)
    print('\nTotal unique bugs: %d   (%.1fs)   reports: %s' % (len(all_findings), time.time() - started, opts.out))
    for i, f in enumerate(all_findings, 1):
        print('  BUG-%02d %-36s %-18s %s' % (i, f['method'], f['exception'], f['location']))
    return 1 if (opts.strict and all_findings) else 0


if __name__ == '__main__':
    sys.exit(main())

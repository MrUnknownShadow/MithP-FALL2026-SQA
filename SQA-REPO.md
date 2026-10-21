# SQA Report: SLI-KUBE (COMP 5710/6710, Fall 2026)

Team: TEAMNAME. Members: see `README.md`.

## 1. Summary

1. Subject: SLI-KUBE (KubeSec), a Python tool that scans Kubernetes manifests and Helm values for security misconfigurations.
2. Fuzzing: `fuzz.py` fuzzes 10 methods and found 10 unique bugs (seed 5710). Three are reachable from ordinary YAML files.
3. Forensics: 10 `scanner.py` methods now log inputs, file hashes, results and exceptions to `forensics.log`. A run over all 76 test manifests recorded 760 calls, 760 returns and 0 errors.
4. CI: a GitHub Actions workflow runs the unit tests, `fuzz.py` and the forensics run on every push, then uploads the evidence.
5. Extra findings from running the project: 6 further defects (section 6).

## 2. Setup

1. Unpacked `slikube.zip`. The repo root is the `KubeSec-master` folder.
2. Python 3.10 locally, 3.11 in CI. Dependencies: pandas, numpy, ruamel.yaml, sarif-om, jschema-to-python, typer, pytest. `yq` v4 is required by `parser.show_line_for_paths`.
3. Baseline before any change: `TEST_PARSING.py` 23 of 23 pass. Full suite 101 pass, 64 fail. The 64 failures are 53 tests reading `/Users/arahman/...` files that are not in the zip, 10 tests unpacking 4 values from `scanSingleManifest` (it returns 3), and 1 `KeyError` (defect D2 below). None come from our changes: the totals were identical after instrumenting.

## 3. Fuzzing (`fuzz.py`)

### 3.1 Design

1. Seeded random generator (default seed 5710, 1000 calls per method). Same seed gives the same bugs.
2. Inputs: empty and huge strings, project keywords, unicode and control characters, ints beyond 64 bits, NaN and infinity, bytes, None, nested dicts and lists with non-string keys, 500 to 3000 level deep structures, and binary or YAML-like temp files.
3. Each call has a 3 second alarm to detect hangs. Any exception is recorded once per (type, code location), with the first input that caused it.
4. Output: `fuzz_results/fuzz_report.md` and `.json`. Exit code is 0 by default; `--strict` exits 1 when a bug is found.

### 3.2 Methods fuzzed

| # | Method | Bugs |
|---|---|---|
| 1 | `parser.checkIfWeirdYAML` | 1 |
| 2 | `parser.keyMiner` | 1 |
| 3 | `parser.getKeyRecursively` | 1 |
| 4 | `parser.getValsFromKey` | 1 |
| 5 | `parser.getSingleDict4MultiDocs` | 2 |
| 6 | `parser.checkIfValidHelm` | 1 |
| 7 | `parser.find_json_path_keys` | 2 |
| 8 | `scanner.checkIfValidSecret` | 0 |
| 9 | `scanner.scanUserName` | 0 |
| 10 | `parser.count_initial_comment_line` | 1 |

### 3.3 Bugs found

| ID | Method | Failure | Cause and fix | Reachable from a YAML file? |
|---|---|---|---|---|
| BUG-01 | `checkIfWeirdYAML` | `TypeError` for non-string input | `x in yaml_script` on a non-str (parser.py:29). Check `isinstance(yaml_script, str)`. | No, callers pass paths |
| BUG-02 | `keyMiner` | `RecursionError` | Recursive traversal with no depth limit. Use an explicit stack. | Only with extreme nesting |
| BUG-03 | `getKeyRecursively` | `RecursionError` | Same cause. | Only with extreme nesting |
| BUG-04 | `getValsFromKey` | `RecursionError` | Same cause. | Only with extreme nesting |
| BUG-05 | `getSingleDict4MultiDocs` | `IndexError` | `dic = dic[0]` on an empty list (parser.py:379). Skip empty lists. | **Yes**: a file whose document is `[]` |
| BUG-06 | `getSingleDict4MultiDocs` | `TypeError` | `k_ + '.YAML.DOC.'` fails when a repeated key is not a string (parser.py:402). Use `str(k_)`. | **Yes**: multi-document YAML that repeats an int key (`1: a`, `---`, `1: b`) |
| BUG-07 | `checkIfValidHelm` | `TypeError` for non-string input | Substring tests on bytes or None (parser.py:131). Type check. | No |
| BUG-08 | `find_json_path_keys` | `TypeError` for None, float, bytes or tuple keys | `regex.match(key)` needs a string (parser.py:255). Convert with `str(key)` or skip. | **Yes**: a manifest containing `~: 1` crashes `loadMultiYAML` |
| BUG-09 | `find_json_path_keys` | `RecursionError` | Recursive traversal. | Only with extreme nesting |
| BUG-10 | `count_initial_comment_line` | `UnicodeDecodeError` | File opened with the default encoding and no error handling (parser.py:207). Pass `encoding='utf-8', errors='replace'`. | Unlikely: non-UTF-8 files are skipped earlier |

Reproducers for the three bugs reachable from a YAML file (BUG-05, BUG-06, BUG-08):

```python
import parser
parser.getSingleDict4MultiDocs(parser.loadMultiYAML('empty_list.yaml'))   # file content: []      -> IndexError
parser.loadMultiYAML('null_key.yaml')                                      # file content: ~: 1   -> TypeError
parser.getSingleDict4MultiDocs(parser.loadMultiYAML('int_keys.yaml'))      # content: 1: a / --- / 1: b  -> TypeError
```

`checkIfValidSecret` and `scanUserName` survived all inputs because they guard with `isinstance` before use.

## 4. Forensics (`forensics.py`, `scanner.py`)

### 4.1 Methods modified

`scanForOverPrivileges`, `scanSingleManifest`, `scanForMissingSecurityContext`, `scanForDefaultNamespace`, `scanForResourceLimits`, `scanForRollingUpdates`, `scanForMissingNetworkPolicy`, `scanForTruePID`, `scanForTrueIPC`, `scanDockerSock`.

None of these overlap with the fuzzed methods.

### 4.2 What each method now does

1. On entry: `forensics.enter(...)` logs UTC timestamp, process id, method name, every argument, and the SHA-256 of any file argument. The hash shows exactly which version of a manifest was analysed.
2. On return: `forensics.leave(...)` logs duration, result type, size and a preview, then returns the result unchanged.
3. On exception: `forensics.error(...)` logs exception type, message and full traceback, then the original exception is re-raised. Behaviour is unchanged.
4. Format: one JSON object per line in `forensics.log` (override the path with `FORENSICS_LOG`). Searchable with `grep` or `jq`.

Example (from `evidence/forensics_sample.jsonl`):

```
{"event": "enter", "func": "scanDockerSock", "args": {"path_script": "'TEST_ARTIFACTS/ANOTHER.DOCKERSOCK.yaml'"}, "file_sha256": {"path_script": "6b8d5145..."}, ...}
{"event": "exit",  "func": "scanDockerSock", "result": "{1: []}", "result_type": "dict", "seconds": 0.020105, ...}
{"event": "error", "func": "scanForTruePID", "exc_type": "FileNotFoundError", "exc_msg": "[Errno 2] No such file or directory: 'TEST_ARTIFACTS/missing.yaml'", ...}
```

### 4.3 Verification

1. `TEST_FORENSICS.py` checks all 10 methods: a successful call logs `enter` then `exit`; a call on a missing file logs `enter` then `error` and still raises `FileNotFoundError`. Result: 3 tests and 20 subtests pass.
2. `run_forensics_demo.py` runs the 10 methods over the 76 files in `TEST_ARTIFACTS/`: enter=760, exit=760, error=0 (`evidence/forensics_demo_summary.txt`).
3. The tests caught a real mistake in the first version of the instrumentation (see lesson 4).

## 5. Continuous integration (`.github/workflows/python.build.yml`)

Triggers: every push, every pull request, manual run.

1. Check out, set up Python 3.11.
2. Install dependencies and `yq`.
3. `pytest TEST_PARSING.py TEST_FORENSICS.py`.
4. `python fuzz.py`, and append the fuzz report to the job summary.
5. `python run_forensics_demo.py`.
6. Upload `fuzz_results/` and `forensics.log` as the `sqa-evidence` artifact (runs even if an earlier step fails).

The fuzz step does not fail the build when it finds bugs, because the bugs are known and documented here. Use `python fuzz.py --strict` to make new bugs fail the build.

## 6. Other defects found while running the project

| ID | Defect | Evidence |
|---|---|---|
| D1 | `main.py` uses `typer` and `Path` without importing them, so importing it raises `NameError`; `TEST_INTEGRATION.py` cannot run. | `import main` |
| D2 | `parser.show_line_for_paths` prints `key_jsonpath_mapping[key]` before checking that the key exists (parser.py:323). Keys that are list indexes raise `KeyError`. `runScanner` crashes on `TEST_ARTIFACTS/nginx.present.yaml` through `scanForHTTP`. Fix: use `.get(key)`. | `scanner.runScanner('TEST_ARTIFACTS')` |
| D3 | `from sarif_om import *` in `scanner.py` replaces the built-in `Exception` with a SARIF class, so `except Exception` fails with `TypeError`. | Caught by `TEST_FORENSICS.py` |
| D4 | `requirements.txt` is UTF-16 and pins Windows and MKL packages (`pywin32`, `mkl-*`), so it does not install on Linux. CI installs a minimal list instead. | `pip install -r requirements.txt` |
| D5 | 53 tests depend on `/Users/arahman/...` paths outside the repo. | pytest output |
| D6 | 10 tests unpack 4 values from `scanSingleManifest`, which returns 3. | pytest output |

D1 to D6 and BUG-01 to BUG-10 are reported, not fixed, so the evidence stays reproducible.

## 7. Lessons learned

1. Fuzzing finds robustness gaps cheaply. A small input generator produced ten distinct bugs in under a second, and the seed makes every one repeatable.
2. Deduplicate by root cause. Grouping by message produced 25 "bugs"; grouping by exception type and code location produced 10. RecursionError needed the entry frame, because the failing line depends on the stack depth.
3. Not every crash matters equally. Passing `None` to a path checker is a contract violation; an empty YAML list or a `~:` key is a valid input that breaks the tool. Reachability decides severity.
4. Forensics code needs tests too. The first instrumentation caught the wrong `Exception` (shadowed by `sarif_om`) and mishandled a tuple return; the tests found both quickly.
5. Logs are most useful when structured. JSON lines plus a file hash let us answer "what ran, on which version of which file, and what came back".
6. CI must be reproducible. The original workflow ran one test file with dependencies installed one by one. Pinning the Python version, installing `yq` explicitly and saving artifacts made the results comparable between local and CI runs.
7. Existing tests can rot. 63 of 64 failing tests came from hardcoded paths and a changed return shape. Tests that depend on the author's machine give no protection to anyone else.

## 8. Reproduce

```bash
pip install pytest pandas numpy PyYAML ruamel.yaml sarif-om jschema-to-python typer
python fuzz.py --seed 5710
python -m pytest -q TEST_PARSING.py TEST_FORENSICS.py
python run_forensics_demo.py
```

## 9. Screenshots

Add these files to `screenshots/` after the first GitHub Actions run:

1. `actions_run_green.png`: workflow run page showing all steps.
2. `actions_fuzz_summary.png`: job summary with the fuzz report.
3. `actions_artifacts.png`: the `sqa-evidence` artifact.
4. `local_fuzz.png`: terminal output of `python fuzz.py`.
5. `local_forensics.png`: terminal output of `python run_forensics_demo.py` and a few lines of `forensics.log`.

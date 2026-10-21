# Fuzzing report

seed=5710, iterations per method=1000

| Method | Calls | Crashing calls | Unique bugs |
|---|---|---|---|
| parser.checkIfWeirdYAML | 1000 | 111 | 1 |
| parser.keyMiner | 1000 | 11 | 1 |
| parser.getKeyRecursively | 1000 | 8 | 1 |
| parser.getValsFromKey | 1000 | 8 | 1 |
| parser.getSingleDict4MultiDocs | 1000 | 125 | 2 |
| parser.checkIfValidHelm | 1000 | 92 | 1 |
| parser.find_json_path_keys | 1000 | 174 | 2 |
| scanner.checkIfValidSecret | 1000 | 0 | 0 |
| scanner.scanUserName | 1000 | 0 | 0 |
| parser.count_initial_comment_line | 1000 | 310 | 1 |

## Findings

### BUG-01  parser.checkIfWeirdYAML -> TypeError
- message: `argument of type 'bool' is not iterable`
- raised at: `parser.py:29 in <genexpr>`
- occurrences: 111
- first input: `(False,)`

### BUG-02  parser.keyMiner -> RecursionError
- message: `maximum recursion depth exceeded in comparison`
- raised at: `parser.py in keyMiner`
- occurrences: 11
- first input: `<repr failed: structure too deep>`

### BUG-03  parser.getKeyRecursively -> RecursionError
- message: `maximum recursion depth exceeded while calling a Python object`
- raised at: `parser.py in getKeyRecursively`
- occurrences: 8
- first input: `<repr failed: structure too deep>`

### BUG-04  parser.getValsFromKey -> RecursionError
- message: `maximum recursion depth exceeded while calling a Python object`
- raised at: `parser.py in getValsFromKey`
- occurrences: 8
- first input: `<repr failed: structure too deep>`

### BUG-05  parser.getSingleDict4MultiDocs -> IndexError
- message: `list index out of range`
- raised at: `parser.py:379 in getSingleDict4MultiDocs`
- occurrences: 111
- first input: `([b'\xf9\x86\x02\n', [<Opaque>], []],)`

### BUG-06  parser.getSingleDict4MultiDocs -> TypeError
- message: `unsupported operand type(s) for +: 'int' and 'str'`
- raised at: `parser.py:402 in getSingleDict4MultiDocs`
- occurrences: 14
- first input: `([{(1, 2): True, 0: [{}, 'pwdxmzIWmx!', -inf], '.travis.yml': <Opaque>, "^';H{kw$3s0{FGémR6A\nh<IP{]": '.travis.yml\\u<M9('}, {2.5: {'.github/E\\_%X{': [True, ''], 'W<myAo?Ep"t中nxg[e(]rWxiXO?"2🙂^+\tyR...<341 chars>`

### BUG-07  parser.checkIfValidHelm -> TypeError
- message: `a bytes-like object is required, not 'str'`
- raised at: `parser.py:131 in checkIfValidHelm`
- occurrences: 92
- first input: `(b'',)`

### BUG-08  parser.find_json_path_keys -> TypeError
- message: `cannot use a string pattern on a bytes-like object`
- raised at: `parser.py:255 in find_json_path_keys`
- occurrences: 157
- first input: `([{'admin_pass': None, b'k': {}, 'crt': ["vrhM(H^j\\_|'T<\r?**wwjU中iXB3中E中,L", (1, 2)]}, 'was"t<G\\$ >aN.\\Ozxlf@?', b'', ''],)`

### BUG-09  parser.find_json_path_keys -> RecursionError
- message: `maximum recursion depth exceeded in comparison`
- raised at: `parser.py in find_json_path_keys`
- occurrences: 17
- first input: `<repr failed: structure too deep>`

### BUG-10  parser.count_initial_comment_line -> UnicodeDecodeError
- message: `'utf-8' codec can't decode byte 0xe2 in position 0: invalid continuation byte`
- raised at: `parser.py:207 in count_initial_comment_line`
- occurrences: 310
- first input: `('<tmpdir>/fuzz_37306954.yaml',)`

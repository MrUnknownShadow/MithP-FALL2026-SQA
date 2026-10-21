'''
Forensics helper for SLI-KUBE (COMP 5710/6710 SQA project).

Every instrumented method records three kinds of events to a JSON-lines
log file (default: forensics.log next to this file, override with the
FORENSICS_LOG environment variable):

  enter : timestamp, pid, function, arguments, SHA-256 of any file argument
  exit  : function, duration, type/size/preview of the return value
  error : function, exception type, message, full traceback

JSON lines keep each event self-contained so the log can be searched with
grep/jq and replayed in order after an incident.
'''
import hashlib
import json
import logging
import os
import threading
import time
import traceback
from datetime import datetime, timezone

LOG_PATH    = os.environ.get('FORENSICS_LOG', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'forensics.log'))
MAX_PREVIEW = 300

_lock   = threading.Lock()
_logger = logging.getLogger('slikube.forensics')
_logger.setLevel(logging.INFO)
_logger.propagate = False
if not _logger.handlers:
    _handler = logging.FileHandler(LOG_PATH, encoding='utf-8')
    _handler.setFormatter(logging.Formatter('%(message)s'))
    _logger.addHandler(_handler)


def _preview(obj):
    try:
        text = repr(obj)
    except Exception as exc:
        text = '<unrepresentable %s: %s>' % (type(obj).__name__, exc)
    if len(text) > MAX_PREVIEW:
        text = text[:MAX_PREVIEW] + '...<%d chars>' % len(text)
    return text


def _sha256(path):
    try:
        if isinstance(path, str) and os.path.isfile(path):
            digest = hashlib.sha256()
            with open(path, 'rb') as handle:
                for chunk in iter(lambda: handle.read(65536), b''):
                    digest.update(chunk)
            return digest.hexdigest()
    except OSError:
        pass
    return None


def _emit(record):
    record['ts']  = datetime.now(timezone.utc).isoformat()
    record['pid'] = os.getpid()
    with _lock:
        _logger.info(json.dumps(record, sort_keys=True, default=str))


def enter(func_name, **kwargs):
    '''Log a call and return a context token for leave()/error().'''
    hashes = {k: _sha256(v) for k, v in kwargs.items() if _sha256(v)}
    _emit({'event': 'enter', 'func': func_name,
           'args': {k: _preview(v) for k, v in kwargs.items()},
           'file_sha256': hashes})
    return {'func': func_name, 'start': time.perf_counter()}


def leave(ctx, result):
    '''Log the return value and hand it back unchanged.'''
    size = len(result) if hasattr(result, '__len__') else None
    _emit({'event': 'exit', 'func': ctx['func'],
           'seconds': round(time.perf_counter() - ctx['start'], 6),
           'result_type': type(result).__name__, 'result_size': size,
           'result': _preview(result)})
    return result


def error(ctx, exc):
    '''Log an exception raised inside an instrumented method.'''
    _emit({'event': 'error', 'func': ctx['func'],
           'seconds': round(time.perf_counter() - ctx['start'], 6),
           'exc_type': type(exc).__name__, 'exc_msg': str(exc),
           'traceback': traceback.format_exc()})

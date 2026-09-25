#!/usr/bin/env python3
"""angrop subprocess worker for compare-tools.py.

Runs under whatever interpreter has angr and angrop importable — normally the
harness's own .venv (see shell.nix / requirements.txt) — so that a crashing/OOMing
chain search cannot take the whole comparison run down with it, and so angr's
heavy import cost is paid in a throwaway process.

Given one target binary and one angrop "chain description" module (a file that
defines ``build(project, rop) -> RopChain``), it loads the binary, discovers
gadgets, builds the chain, and prints exactly ONE JSON line to stdout::

    {"found": bool, "extract_seconds": float|null, "seconds": float|null,
     "status": "found|not-found|timeout|load-timeout|error", "chain": str}

Gadget loading and chain construction are timed and bounded separately, matching
compare-tools.py's rop3 runner. ``extract_seconds`` measures find_gadgets() (the
gadget-loading phase, bounded by ``--load-timeout``); ``seconds`` measures build()
(the construction phase, bounded by ``--build-timeout``). Both exclude
interpreter/angr import startup, so they are comparable to rop3's gadgets() and
search. A load-phase timeout is reported ``status="load-timeout"`` (seconds null);
a construction-phase timeout ``status="timeout"``. ``chain`` is angrop's assembled
payload as text (``RopChain.payload_str()``), empty unless ``found``. Any
diagnostic text goes to stderr; stdout carries the JSON result only.
"""
import argparse
import importlib.util
import json
import os
import sys
import threading
import time

# Set once each phase completes, so its watchdog stands down. The build watchdog
# reads the measured load time so a construction timeout still reports it.
_LOAD_DONE = threading.Event()
_BUILD_DONE = threading.Event()
_EXTRACT = {"seconds": None}


def _load_watchdog(budget):
    """Bound the gadget-loading phase from a side thread; hard-exit on expiry.

    A signal/SIGALRM deadline does not work here: angrop arms its own SIGALRM for
    per-gadget timeouts and clobbers ours, so the alarm never reaches us and a
    full-libc load (~25 min) would only stop when the parent kills the process.
    A thread waiting on an Event is immune to that — it fires regardless of what
    angr is doing in C — and ``os._exit`` guarantees the parent still gets a
    clean 'load-timeout' line at the budget. Disarmed by _LOAD_DONE once loading
    finishes."""
    if not _LOAD_DONE.wait(budget):
        _emit(False, budget, None, "load-timeout")
        os._exit(0)


def _build_watchdog(budget):
    """Bound the chain-construction phase (same mechanism as _load_watchdog).
    On expiry it still reports the measured load time in extract_seconds."""
    if not _BUILD_DONE.wait(budget):
        _emit(False, _EXTRACT["seconds"], budget, "timeout")
        os._exit(0)


def _load_spec(path):
    """Load the chain-description module and return its build() callable."""
    spec = importlib.util.spec_from_file_location("angrop_chain_spec", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    build = getattr(mod, "build", None)
    if not callable(build):
        raise AttributeError(f"{path}: no build(project, rop) function")
    return build


def _emit(found, extract_seconds, seconds, status, chain=""):
    """Print the single result line to stdout and flush."""
    print(json.dumps({
        "found": bool(found),
        "extract_seconds": round(extract_seconds, 4) if extract_seconds is not None else None,
        "seconds": round(seconds, 4) if seconds is not None else None,
        "status": status,
        "chain": chain or "",
    }))
    sys.stdout.flush()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--spec", required=True, help="angrop chain-description .py")
    ap.add_argument("--load-timeout", type=float, default=0,
                    help="seconds for find_gadgets() (0 = unlimited)")
    ap.add_argument("--build-timeout", type=float, default=0,
                    help="seconds for build() (0 = unlimited)")
    args = ap.parse_args(argv)

    try:
        import angr
        import angrop  # noqa: F401  (registers the ROP analysis)
        from angrop.errors import RopException
    except Exception as exc:  # ImportError, and angr's own load-time errors
        print(f"[angrop_worker] cannot import angr/angrop: {exc}", file=sys.stderr)
        return _emit(False, None, None, "error")

    try:
        build = _load_spec(args.spec)
    except Exception as exc:
        print(f"[angrop_worker] bad spec {args.spec}: {exc}", file=sys.stderr)
        return _emit(False, None, None, "error")

    # --- Load phase: angr.Project + find_gadgets(), bounded by --load-timeout --
    if args.load_timeout:
        threading.Thread(target=_load_watchdog, args=(args.load_timeout,),
                         daemon=True).start()
    t0 = time.perf_counter()
    try:
        proj = angr.Project(args.binary, auto_load_libs=False)
        rop = proj.analyses.ROP()
        rop.find_gadgets_single_threaded()
        extract = time.perf_counter() - t0
    except MemoryError:
        print("[angrop_worker] out of memory (load)", file=sys.stderr)
        _LOAD_DONE.set()
        return _emit(False, time.perf_counter() - t0, None, "error")
    except Exception as exc:
        print(f"[angrop_worker] {type(exc).__name__}: {exc} (load)", file=sys.stderr)
        _LOAD_DONE.set()
        return _emit(False, time.perf_counter() - t0, None, "error")
    _EXTRACT["seconds"] = extract
    _LOAD_DONE.set()   # stand the load watchdog down before starting the build

    # --- Build phase: build(), bounded by --build-timeout ----------------------
    if args.build_timeout:
        threading.Thread(target=_build_watchdog, args=(args.build_timeout,),
                         daemon=True).start()
    t1 = time.perf_counter()
    try:
        chain = build(proj, rop)
        seconds = time.perf_counter() - t1
        try:
            text = chain.payload_str()
        except Exception:
            text = ""
        found, status = True, "found"
    except (RopException, StopIteration):
        found, status, seconds, text = False, "not-found", time.perf_counter() - t1, ""
    except MemoryError:
        print("[angrop_worker] out of memory (build)", file=sys.stderr)
        found, status, seconds, text = False, "error", time.perf_counter() - t1, ""
    except Exception as exc:
        print(f"[angrop_worker] {type(exc).__name__}: {exc} (build)", file=sys.stderr)
        found, status, seconds, text = False, "error", time.perf_counter() - t1, ""
    # Stand the watchdog down before emitting so it can't race a spurious timeout
    # line on top of this verdict.
    _BUILD_DONE.set()
    return _emit(found, extract, seconds, status, text)


if __name__ == "__main__":
    sys.exit(main())

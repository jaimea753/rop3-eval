#!/usr/bin/env python3
"""angrop subprocess worker for compare-tools.py.

Runs under whatever interpreter has angr and angrop importable — normally the
harness's own .venv (see shell.nix / requirements.txt) — so that a crashing/OOMing
chain search cannot take the whole comparison run down with it, and so angr's
heavy import cost is paid in a throwaway process.

Given one target binary and one angrop "chain description" module (a file that
defines ``build(project, rop) -> RopChain``), it loads the binary, discovers
gadgets, builds the chain, and prints exactly ONE JSON line to stdout::

    {"found": bool, "seconds": float|null,
     "status": "found|not-found|timeout|error", "chain": str}

``seconds`` measures find_gadgets() + build() (the tool's own work), excluding
interpreter/angr import startup, so it is comparable to rop3's gadgets()+search.
``chain`` is angrop's assembled payload as text (``RopChain.payload_str()``),
empty unless ``found``. Any diagnostic text goes to stderr; stdout carries the
JSON result only.
"""
import argparse
import importlib.util
import json
import os
import sys
import threading
import time

# Set once the search has produced a verdict, so the watchdog stands down.
_DONE = threading.Event()


def _watchdog(budget):
    """Enforce the search budget from a side thread and hard-exit on expiry.

    A signal/SIGALRM deadline does not work here: angrop arms its own SIGALRM for
    per-gadget timeouts and clobbers ours, so the alarm never reaches us and a
    full-libc search (~25 min) would only stop when the parent kills the process.
    A thread waiting on an Event is immune to that — it fires regardless of what
    angr is doing in C — and ``os._exit`` guarantees the parent still gets a
    clean 'timeout' line at the budget. Disarmed by _DONE once a verdict lands."""
    if not _DONE.wait(budget):
        _emit(False, budget, "timeout")
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


def _emit(found, seconds, status, chain=""):
    """Print the single result line to stdout and flush."""
    print(json.dumps({
        "found": bool(found),
        "seconds": round(seconds, 4) if seconds is not None else None,
        "status": status,
        "chain": chain or "",
    }))
    sys.stdout.flush()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--spec", required=True, help="angrop chain-description .py")
    ap.add_argument("--timeout", type=float, default=0,
                    help="seconds for find_gadgets()+build() (0 = unlimited)")
    args = ap.parse_args(argv)

    try:
        import angr
        import angrop  # noqa: F401  (registers the ROP analysis)
        from angrop.errors import RopException
    except Exception as exc:  # ImportError, and angr's own load-time errors
        print(f"[angrop_worker] cannot import angr/angrop: {exc}", file=sys.stderr)
        return _emit(False, None, "error")

    try:
        build = _load_spec(args.spec)
    except Exception as exc:
        print(f"[angrop_worker] bad spec {args.spec}: {exc}", file=sys.stderr)
        return _emit(False, None, "error")

    if args.timeout:
        threading.Thread(target=_watchdog, args=(args.timeout,),
                         daemon=True).start()

    t0 = time.perf_counter()
    try:
        proj = angr.Project(args.binary, auto_load_libs=False)
        rop = proj.analyses.ROP()
        rop.find_gadgets_single_threaded()
        chain = build(proj, rop)
        seconds = time.perf_counter() - t0
        try:
            text = chain.payload_str()
        except Exception:
            text = ""
        found, status, secs = True, "found", seconds
    except (RopException, StopIteration):
        found, status, secs, text = False, "not-found", time.perf_counter() - t0, ""
    except MemoryError:
        print("[angrop_worker] out of memory", file=sys.stderr)
        found, status, secs, text = False, "error", time.perf_counter() - t0, ""
    except Exception as exc:
        print(f"[angrop_worker] {type(exc).__name__}: {exc}", file=sys.stderr)
        found, status, secs, text = False, "error", time.perf_counter() - t0, ""
    # Stand the watchdog down before emitting so it can't race a spurious timeout
    # line on top of this verdict.
    _DONE.set()
    return _emit(found, secs, status, text)


if __name__ == "__main__":
    sys.exit(main())

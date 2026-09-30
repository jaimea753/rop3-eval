#!/usr/bin/env python3
"""ropium subprocess worker for compare-tools.py.

ropium has no working pip package, so it is vendored and built locally into a
gitignored .ropium/ at the repo root (see utils/build_ropium.sh); this worker
imports the compiled extension from .ropium/bin/ (override with ROPIUM_HOME).
Running it in a throwaway subprocess means a crashing/OOMing chain search cannot
take the whole comparison run down with it, and ropium's gadget-database build
cost is paid in a throwaway process. The compiled ropium.so needs libcapstone on
the loader path at import (shell.nix puts it on LD_LIBRARY_PATH).

Given one target binary and one ropium "chain description" (a file holding a
single ropium query string, e.g. ``sys_execve("/bin/sh", 0, 0)``) plus the
target architecture, it loads the binary, compiles the query, and prints exactly
ONE JSON line to stdout::

    {"found": bool, "extract_seconds": float|null, "seconds": float|null,
     "status": "found|not-found|timeout|load-timeout|error", "chain": str}

Gadget loading (``ROPium.load()``) and chain compilation (``ROPium.compile()``)
are timed and bounded separately, matching compare-tools.py's rop3/angrop
runners. ``extract_seconds`` measures load() (bounded by ``--load-timeout``);
``seconds`` measures compile() (bounded by ``--build-timeout``). Both exclude
interpreter/ropium import startup, so they are comparable. A load-phase timeout
is reported ``status="load-timeout"`` (seconds null); a compile-phase timeout
``status="timeout"``. ``chain`` is ropium's assembled chain as text
(``ROPChain.dump()``), empty unless ``found``. ropium supports x86/x86_64 only;
diagnostic text goes to stderr, stdout carries the JSON result only.
"""
import argparse
import json
import os
import sys
import threading
import time

# Import ropium from the locally-built, gitignored checkout. ROPIUM_HOME overrides
# the default .ropium/ at the repo root; its bin/ holds the compiled ropium.so.
_ROPIUM_HOME = os.environ.get("ROPIUM_HOME") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".ropium")
_ROPIUM_BIN = os.path.join(_ROPIUM_HOME, "bin")
if os.path.isdir(_ROPIUM_BIN):
    sys.path.insert(0, _ROPIUM_BIN)

# Set once each phase completes, so its watchdog stands down. The build watchdog
# reads the measured load time so a compile timeout still reports it.
_LOAD_DONE = threading.Event()
_BUILD_DONE = threading.Event()
_EXTRACT = {"seconds": None}


def _load_watchdog(budget):
    """Bound the gadget-loading phase from a side thread; hard-exit on expiry.

    A thread waiting on an Event fires regardless of what ropium's native code is
    doing, and ``os._exit`` guarantees the parent still gets a clean
    'load-timeout' line at the budget. Disarmed by _LOAD_DONE once loading
    finishes (same mechanism as utils/angrop_worker.py)."""
    if not _LOAD_DONE.wait(budget):
        _emit(False, budget, None, "load-timeout")
        os._exit(0)


def _build_watchdog(budget):
    """Bound the chain-compilation phase (same mechanism as _load_watchdog).
    On expiry it still reports the measured load time in extract_seconds."""
    if not _BUILD_DONE.wait(budget):
        _emit(False, _EXTRACT["seconds"], budget, "timeout")
        os._exit(0)


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
    ap.add_argument("--query", required=True, help="file with one ropium query")
    ap.add_argument("--arch", required=True, choices=["x86", "x86_64"],
                    help="target architecture (ropium supports x86/x86_64 only)")
    ap.add_argument("--load-timeout", type=float, default=0,
                    help="seconds for ROPium.load() (0 = unlimited)")
    ap.add_argument("--build-timeout", type=float, default=0,
                    help="seconds for ROPium.compile() (0 = unlimited)")
    args = ap.parse_args(argv)

    try:
        import ropium
    except Exception as exc:  # ImportError (not built?), missing libcapstone, etc.
        print(f"[ropium_worker] cannot import ropium from {_ROPIUM_BIN!r}: {exc}\n"
              f"  (build it with utils/build_ropium.sh)", file=sys.stderr)
        return _emit(False, None, None, "error")

    # ropium's arch is an ARCH enum (ARCH.X86 / ARCH.X64), not module constants.
    arch_const = {"x86": ropium.ARCH.X86, "x86_64": ropium.ARCH.X64}[args.arch]
    try:
        with open(args.query) as f:
            query = f.read().strip()
    except Exception as exc:
        print(f"[ropium_worker] bad query {args.query}: {exc}", file=sys.stderr)
        return _emit(False, None, None, "error")
    if not query:
        print(f"[ropium_worker] empty query {args.query}", file=sys.stderr)
        return _emit(False, None, None, "error")

    # --- Load phase: ROPium(arch) + load(), bounded by --load-timeout ----------
    if args.load_timeout:
        threading.Thread(target=_load_watchdog, args=(args.load_timeout,),
                         daemon=True).start()
    t0 = time.perf_counter()
    try:
        ctx = ropium.ROPium(arch_const)
        ctx.load(args.binary)
        extract = time.perf_counter() - t0
    except MemoryError:
        print("[ropium_worker] out of memory (load)", file=sys.stderr)
        _LOAD_DONE.set()
        return _emit(False, time.perf_counter() - t0, None, "error")
    except Exception as exc:
        print(f"[ropium_worker] {type(exc).__name__}: {exc} (load)", file=sys.stderr)
        _LOAD_DONE.set()
        return _emit(False, time.perf_counter() - t0, None, "error")
    _EXTRACT["seconds"] = extract
    _LOAD_DONE.set()   # stand the load watchdog down before starting the build

    # --- Build phase: compile(), bounded by --build-timeout --------------------
    if args.build_timeout:
        threading.Thread(target=_build_watchdog, args=(args.build_timeout,),
                         daemon=True).start()
    t1 = time.perf_counter()
    try:
        chain = ctx.compile(query)
        seconds = time.perf_counter() - t1
        # ropium returns a ROPChain on success and a falsy value (None / empty
        # chain) when it cannot satisfy the query; it does not raise for that.
        if chain:
            try:
                text = chain.dump()
            except Exception:
                text = str(chain)
            found, status = True, "found"
        else:
            found, status, text = False, "not-found", ""
    except MemoryError:
        print("[ropium_worker] out of memory (compile)", file=sys.stderr)
        found, status, seconds, text = False, "error", time.perf_counter() - t1, ""
    except Exception as exc:
        print(f"[ropium_worker] {type(exc).__name__}: {exc} (compile)", file=sys.stderr)
        found, status, seconds, text = False, "error", time.perf_counter() - t1, ""
    # Stand the watchdog down before emitting so it can't race a spurious timeout
    # line on top of this verdict.
    _BUILD_DONE.set()
    return _emit(found, extract, seconds, status, text)


if __name__ == "__main__":
    sys.exit(main())

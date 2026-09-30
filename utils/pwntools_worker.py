#!/usr/bin/env python3
"""pwntools subprocess worker for compare-tools.py.

Runs under whatever interpreter has pwntools (pwnlib) importable — normally the
harness's own .venv (see shell.nix / requirements.txt) — so that a crashing/
OOMing chain build cannot take the whole comparison run down with it, and so
pwntools' gadget discovery cost is paid in a throwaway process.

Given one target binary and one pwntools "chain description" module (a file that
defines ``build(elf, rop)``, which mutates ``rop`` — e.g.
``rop.call("mprotect", [0x1000, 0x1000, 7])`` — leaving the actual chain assembly
to the worker's ``rop.chain()`` call), it loads the binary, discovers gadgets,
builds the chain, and prints exactly ONE JSON line to stdout::

    {"found": bool, "extract_seconds": float|null, "seconds": float|null,
     "status": "found|not-found|timeout|load-timeout|error", "chain": str}

Gadget loading (ELF() + ROP() construction) and chain construction (build() +
rop.chain()) are timed and bounded separately, matching compare-tools.py's
rop3/angrop runners. ``extract_seconds`` measures the load phase (bounded by
``--load-timeout``); ``seconds`` measures the build phase (bounded by
``--build-timeout``). A load-phase timeout is reported ``status="load-timeout"``
(seconds null); a build-phase timeout ``status="timeout"``. ``chain`` is
pwntools' assembled chain as text (``ROP.dump()``), empty unless ``found``.

To keep the reported load time cold-start comparable with the other tools,
pwntools' on-disk gadget cache is redirected to a throwaway per-invocation
directory (XDG_CACHE_HOME, set before importing pwnlib) so each run rediscovers
gadgets. Diagnostic text goes to stderr; stdout carries the JSON result only.
"""
import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import time

# Cold-start fidelity: give pwntools a private, empty gadget cache so this
# invocation cannot reuse gadgets discovered by an earlier one. Must be set
# before pwnlib is imported for it to take effect.
_CACHE_DIR = tempfile.mkdtemp(prefix="pwntools-worker-cache-")
os.environ["XDG_CACHE_HOME"] = _CACHE_DIR

# Set once each phase completes, so its watchdog stands down. The build watchdog
# reads the measured load time so a construction timeout still reports it.
_LOAD_DONE = threading.Event()
_BUILD_DONE = threading.Event()
_EXTRACT = {"seconds": None}


def _load_watchdog(budget):
    """Bound the gadget-loading phase from a side thread; hard-exit on expiry.
    A thread waiting on an Event fires regardless of what pwnlib is doing, and
    ``os._exit`` guarantees the parent still gets a clean 'load-timeout' line at
    the budget. Disarmed by _LOAD_DONE once loading finishes (same mechanism as
    utils/angrop_worker.py)."""
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
    spec = importlib.util.spec_from_file_location("pwntools_chain_spec", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    build = getattr(mod, "build", None)
    if not callable(build):
        raise AttributeError(f"{path}: no build(elf, rop) function")
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
    ap.add_argument("--spec", required=True, help="pwntools chain-description .py")
    ap.add_argument("--load-timeout", type=float, default=0,
                    help="seconds for ELF()+ROP() (0 = unlimited)")
    ap.add_argument("--build-timeout", type=float, default=0,
                    help="seconds for build()+chain() (0 = unlimited)")
    args = ap.parse_args(argv)

    try:
        from pwn import context, ELF, ROP
        from pwnlib.exception import PwnlibException
    except Exception as exc:  # ImportError, and pwnlib's own load-time errors
        print(f"[pwntools_worker] cannot import pwnlib: {exc}", file=sys.stderr)
        _cleanup()
        return _emit(False, None, None, "error")
    context.log_level = "error"   # keep pwntools' logging off stdout

    try:
        build = _load_spec(args.spec)
    except Exception as exc:
        print(f"[pwntools_worker] bad spec {args.spec}: {exc}", file=sys.stderr)
        _cleanup()
        return _emit(False, None, None, "error")

    # --- Load phase: ELF() + ROP() (gadget discovery), bounded by --load-timeout
    if args.load_timeout:
        threading.Thread(target=_load_watchdog, args=(args.load_timeout,),
                         daemon=True).start()
    t0 = time.perf_counter()
    try:
        elf = ELF(args.binary, checksec=False)
        context.clear()
        context.binary = elf          # sets arch/bits/endianness from the ELF
        rop = ROP(elf)
        extract = time.perf_counter() - t0
    except MemoryError:
        print("[pwntools_worker] out of memory (load)", file=sys.stderr)
        _LOAD_DONE.set()
        _cleanup()
        return _emit(False, time.perf_counter() - t0, None, "error")
    except Exception as exc:
        print(f"[pwntools_worker] {type(exc).__name__}: {exc} (load)", file=sys.stderr)
        _LOAD_DONE.set()
        _cleanup()
        return _emit(False, time.perf_counter() - t0, None, "error")
    _EXTRACT["seconds"] = extract
    _LOAD_DONE.set()   # stand the load watchdog down before starting the build

    # --- Build phase: build() + rop.chain(), bounded by --build-timeout ---------
    if args.build_timeout:
        threading.Thread(target=_build_watchdog, args=(args.build_timeout,),
                         daemon=True).start()
    t1 = time.perf_counter()
    try:
        build(elf, rop)
        payload = rop.chain()
        seconds = time.perf_counter() - t1
        try:
            text = rop.dump()
        except Exception:
            text = ""
        # An empty payload means nothing was actually assembled (no chain).
        found = bool(payload)
        status = "found" if found else "not-found"
        if not found:
            text = ""
    except (PwnlibException, StopIteration):
        found, status, seconds, text = False, "not-found", time.perf_counter() - t1, ""
    except MemoryError:
        print("[pwntools_worker] out of memory (build)", file=sys.stderr)
        found, status, seconds, text = False, "error", time.perf_counter() - t1, ""
    except Exception as exc:
        print(f"[pwntools_worker] {type(exc).__name__}: {exc} (build)", file=sys.stderr)
        found, status, seconds, text = False, "error", time.perf_counter() - t1, ""
    # Stand the watchdog down before emitting so it can't race a spurious timeout
    # line on top of this verdict.
    _BUILD_DONE.set()
    _cleanup()
    return _emit(found, extract, seconds, status, text)


def _cleanup():
    shutil.rmtree(_CACHE_DIR, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

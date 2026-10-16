#!/usr/bin/env python3
"""rop4 subprocess worker for compare-tools.py.

rop4 (github.com/jaimea753/rop4) is a Go port of rop3: the same ROPLang chain
language, the same multi-arch gadget/operation/chain search, exposed to Python
through a CGo c-shared library and a thin `Rop4` wrapper that mirrors rop3's
`Rop3`. It has no pip package, so a pinned prebuilt release (the c-shared library
+ the wrapper) is downloaded into a gitignored .rop4/ at the repo root (see
utils/fetch_rop4.sh); this worker imports the wrapper from .rop4/python/ (override
with ROP4_HOME). The release librop4.so statically bundles capstone, so it needs
no libcapstone on the loader path.

Running rop4 in a throwaway subprocess means a crash or OOM in the native Go/CGo
code cannot take the whole comparison run down, exactly as for the
angrop/ropium/pwntools workers. Because rop4 reuses rop3's ROPLang, the chain
file handed in is just the rop3 reference chain (ropchains/rop4/<goal>_<arch>.txt
is a copy of ropchains/rop3/<goal>_<arch>.txt).

Given one target binary (one or more files for a bundle), one ROPLang chain file,
the per-arch search depth, and the rop3/rop4 constructor flags, it loads gadgets,
searches for the chain, and prints exactly ONE JSON line to stdout::

    {"found": bool, "extract_seconds": float|null, "seconds": float|null,
     "status": "found|not-found|timeout|load-timeout|error", "chain": str}

Gadget loading (`Rop4(...)` + `.gadgets()`) and chain search (`.ropchain()`) are
timed and bounded separately, matching compare-tools.py's rop3 runner.
`extract_seconds` measures loading (bounded by --load-timeout); `seconds`
measures the search (bounded by --build-timeout). Both exclude interpreter/rop4
import startup, so they are comparable. A load-phase timeout is reported
status="load-timeout" (seconds null); a search-phase timeout status="timeout".
`chain` is the first realized chain rendered as text, empty unless `found`.
Diagnostic text goes to stderr; stdout carries the JSON result line only.
"""
import argparse
import json
import os
import sys
import threading
import time

# Import rop4 from the locally-built, gitignored checkout. ROP4_HOME overrides
# the default .rop4/ at the repo root; its python/ holds the wrapper rop4.py and
# the compiled librop4.so built by utils/build_rop4.sh.
_ROP4_HOME = os.environ.get("ROP4_HOME") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".rop4")
_ROP4_PY = os.path.join(_ROP4_HOME, "python")
if os.path.isdir(_ROP4_PY):
    sys.path.insert(0, _ROP4_PY)

# Set once each phase completes so its watchdog stands down. The build watchdog
# reads the measured load time so a search timeout still reports it.
_LOAD_DONE = threading.Event()
_BUILD_DONE = threading.Event()
_EXTRACT = {"seconds": None}


def _load_watchdog(budget):
    """Bound the gadget-loading phase from a side thread; hard-exit on expiry.

    A thread waiting on an Event fires regardless of what rop4's native Go/CGo
    code is doing (SIGALRM would not interrupt the Go runtime cleanly), and
    os._exit guarantees the parent still gets a clean 'load-timeout' line at the
    budget. Disarmed by _LOAD_DONE once loading finishes (same mechanism as
    utils/ropium_worker.py)."""
    if not _LOAD_DONE.wait(budget):
        _emit(False, budget, None, "load-timeout")
        os._exit(0)


def _build_watchdog(budget):
    """Bound the chain-search phase (same mechanism as _load_watchdog). On expiry
    it still reports the measured load time in extract_seconds."""
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


def _render_gadget(g):
    """One gadget dict -> 'addr: insn; insn' text, tolerant of the exact keys the
    wrapper uses (it returns gadget dicts, not objects). Falls back to repr."""
    if not isinstance(g, dict):
        return str(g)
    addr = g.get("address", g.get("addr"))
    insns = g.get("instructions", g.get("insns", g.get("asm", g.get("text"))))
    if isinstance(insns, (list, tuple)):
        insns = "; ".join(str(i) for i in insns)
    if addr is not None and insns is not None:
        try:
            return f"0x{int(addr):x}: {insns}"
        except (TypeError, ValueError):
            return f"{addr}: {insns}"
    if insns is not None:
        return str(insns)
    return json.dumps(g, default=str)


def _render_chain(chain):
    """A chain (list of gadget dicts) -> newline-joined text."""
    if not isinstance(chain, (list, tuple)):
        return str(chain)
    return "\n".join(_render_gadget(g) for g in chain)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ropchain", required=True, help="ROPLang chain file")
    ap.add_argument("--depth", default="",
                    help="search depth in bytes (empty = rop4's arch default)")
    ap.add_argument("--flags", default="{}",
                    help="JSON object of Rop4() constructor flags")
    ap.add_argument("--load-timeout", type=float, default=0,
                    help="seconds for Rop4() + gadgets() (0 = unlimited)")
    ap.add_argument("--build-timeout", type=float, default=0,
                    help="seconds for ropchain() (0 = unlimited)")
    ap.add_argument("--binary", required=True, nargs="+",
                    help="target binary file(s); multiple for a bundle")
    args = ap.parse_args(argv)

    try:
        from rop4 import Rop4
    except Exception as exc:  # ImportError (not built?), missing libcapstone, etc.
        print(f"[rop4_worker] cannot import rop4 from {_ROP4_PY!r}: {exc}\n"
              f"  (fetch it with utils/fetch_rop4.sh)", file=sys.stderr)
        return _emit(False, None, None, "error")

    try:
        flags = json.loads(args.flags) if args.flags else {}
        if not isinstance(flags, dict):
            raise ValueError("flags must be a JSON object")
    except Exception as exc:
        print(f"[rop4_worker] bad --flags: {exc}", file=sys.stderr)
        return _emit(False, None, None, "error")

    depth = None
    if str(args.depth).strip() not in ("", "null", "None"):
        try:
            depth = int(args.depth)
        except ValueError:
            print(f"[rop4_worker] bad --depth {args.depth!r}", file=sys.stderr)
            return _emit(False, None, None, "error")

    if not os.path.isfile(args.ropchain):
        print(f"[rop4_worker] chain file not found: {args.ropchain}", file=sys.stderr)
        return _emit(False, None, None, "error")

    # --- Load phase: Rop4() + gadgets(), bounded by --load-timeout -------------
    if args.load_timeout:
        threading.Thread(target=_load_watchdog, args=(args.load_timeout,),
                         daemon=True).start()
    t0 = time.perf_counter()
    try:
        rop = Rop4(args.binary, depth=depth, rop=True, jop=False,
                   ropblock=False, **flags)
        rop.gadgets()
        extract = time.perf_counter() - t0
    except MemoryError:
        print("[rop4_worker] out of memory (load)", file=sys.stderr)
        _LOAD_DONE.set()
        return _emit(False, time.perf_counter() - t0, None, "error")
    except Exception as exc:
        print(f"[rop4_worker] {type(exc).__name__}: {exc} (load)", file=sys.stderr)
        _LOAD_DONE.set()
        return _emit(False, time.perf_counter() - t0, None, "error")
    _EXTRACT["seconds"] = extract
    _LOAD_DONE.set()   # stand the load watchdog down before starting the search

    # --- Build phase: ropchain(), bounded by --build-timeout -------------------
    if args.build_timeout:
        threading.Thread(target=_build_watchdog, args=(args.build_timeout,),
                         daemon=True).start()
    t1 = time.perf_counter()
    try:
        # exhaustive=False stops at the first realized chain, matching rop3's
        # next(rop.ropchain(...)) so the search times are comparable. Older
        # wrappers may not take the kwarg, so fall back to the default call.
        try:
            chains = rop.ropchain(args.ropchain, exhaustive=False)
        except TypeError:
            chains = rop.ropchain(args.ropchain)
        seconds = time.perf_counter() - t1
        # rop4.ropchain() returns a list of chains (each a list of gadget dicts);
        # an empty list means no chain was realizable (it does not raise for that).
        if chains:
            found, status, text = True, "found", _render_chain(chains[0])
        else:
            found, status, text = False, "not-found", ""
    except MemoryError:
        print("[rop4_worker] out of memory (search)", file=sys.stderr)
        found, status, seconds, text = False, "error", time.perf_counter() - t1, ""
    except Exception as exc:
        print(f"[rop4_worker] {type(exc).__name__}: {exc} (search)", file=sys.stderr)
        found, status, seconds, text = False, "error", time.perf_counter() - t1, ""
    # Stand the watchdog down before emitting so it can't race a spurious timeout
    # line on top of this verdict.
    _BUILD_DONE.set()
    return _emit(found, extract, seconds, status, text)


if __name__ == "__main__":
    sys.exit(main())

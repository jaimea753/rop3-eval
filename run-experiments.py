"""
Script for running the experiments for the work Evaluating the Execution 
Capabilities of Attackers on Unix Systems using Return Oriented Programming

It is a tweaked version of the original script for
Evaluation of the Executional Power in Windows using Return Oriented Programming

Parts of the code were LLM generated
"""
#!/usr/bin/env python3
import os
import sys
import time
import glob
import signal
import argparse
import gc
import pandas as pd
import pathlib
from concurrent.futures import ProcessPoolExecutor, as_completed

# Provenance (which machine ran this) and the per-library result cache live in
# utils/; both are stdlib + PyYAML only. If they cannot be imported the run
# simply goes ahead uncached rather than failing.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils'))
try:
    import machine_specs
    import benchcache
except ImportError as _import_exc:          # pragma: no cover - optional helpers
    machine_specs = benchcache = None
    print(f"[WARN] utils/machine_specs.py or utils/benchcache.py unavailable "
          f"({_import_exc}): results will not be cached", file=sys.stderr)

ROP_GADGETS = ['add', 'sub', 'neg', 'mov', 'lc', 'ld', 'st', 'xor', 'and', 'or', 'not', 'eqc', 'ltc', 'spa', 'sps', 'jmp', 'gsp']
JOP_GADGETS = ['add', 'sub', 'neg', 'mov', 'lc', 'ld', 'st', 'xor', 'and', 'or', 'not', 'eqc', 'ltc', 'spa', 'sps', 'gsp']

# --- Configurable scan parameters (overridable via a YAML config file) -------
# Built-in defaults; __main__ replaces these from --config when given.
DEFAULT_ROP3_FLAGS = {
    'ret_imm':            True,
    'reg_aliases':        True,
    'keep_contradictory': True,
    'avoid_canary':       False,
}
ROP3_KWARGS   = dict(DEFAULT_ROP3_FLAGS)   # extra Rop3() flag kwargs

# Default rop3 project folder: the bundled `rop3` submodule sitting beside this
# script. Overridable by the positional argument or the config's 'rop3' key.
DEFAULT_ROP3_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rop3')
DEPTH_BY_ARCH = {}                          # {arch_key: depth_bytes | None}
CHAIN_TIMEOUT = None                        # per-ropchain search timeout (s) | None

# --- Benchmark cache / provenance (parent process only) ---------------------
# A library's result is reused when the machine, the rop3 commit, the scan
# parameters and the task list all match; see utils/benchcache.py for what the
# key deliberately ignores (the *contents* of the binaries).
CACHE         = None      # benchcache.Cache, built per run by _make_cache()
CACHE_ENABLED = True
CACHE_REFRESH = False     # re-measure everything, but still write the results
CACHE_DIR     = None
CONFIG        = {}        # the raw config mapping, for hashing and run-meta
CONFIG_PATH   = None
MACHINE       = None      # machine.yaml contents | None
ROP3_COMMIT   = None      # HEAD of the rop3 submodule (+ '-dirty') | None


class _ChainTimeout(Exception):
    """Raised inside a worker when a single ropchain search exceeds CHAIN_TIMEOUT."""


def _alarm_handler(signum, frame):
    raise _ChainTimeout()

try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

def prepare_env(rop3_folder):
    if os.path.isfile(os.path.join(rop3_folder, 'rop3.py')):
        sys.path.append(rop3_folder)
    else:
        print(
            f'{os.path.basename(__file__)}: ERROR: {rop3_folder}: '
            f'Unable to locate rop3.py main file. '
            f'Are you sure this is the rop3 main project folder?'
        )
        sys.exit(-1)

_api_mod      = None
_ropchain_mod = None

def _mem_limit_bytes():
    """Address-space cap for a gadget-scan process: 16 GiB, but never more than
    ~75% of physical RAM. On a small-memory host this keeps a huge binary's scan
    hitting a catchable MemoryError (malloc → NULL) instead of the kernel OOM
    killer sending an uncatchable SIGKILL that would abort the whole run."""
    hard = 16 * 1024 * 1024 * 1024
    try:
        phys = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
        return max(1 * 1024 * 1024 * 1024, min(hard, int(phys * 0.75)))
    except (ValueError, OSError, AttributeError):
        return hard


def _apply_memory_limit():
    if not HAS_RESOURCE:
        return
    cap = _mem_limit_bytes()
    try:
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
    except Exception as e:
        print(f"  [WARN] Could not set memory limit: {e}", file=sys.stderr)


def _worker_init(rop3_folder, rop3_kwargs, depth_by_arch, chain_timeout=None):
    """Initializes the worker process, setting memory limits and loading rop3."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    _apply_memory_limit()

    global _api_mod, _ropchain_mod, ROP3_KWARGS, DEPTH_BY_ARCH, CHAIN_TIMEOUT
    ROP3_KWARGS   = rop3_kwargs
    DEPTH_BY_ARCH = depth_by_arch
    CHAIN_TIMEOUT = chain_timeout
    if rop3_folder not in sys.path:
        sys.path.insert(0, rop3_folder)

    import rop3.api      as _a
    import rop3.ropchain as _r
    _api_mod      = _a
    _ropchain_mod = _r

def _arch_key(arch):
    """Short config key for an rop3 Architecture (x86 / x86_64 / aarch64 /
    riscv64), used to look up a per-architecture depth. Falls back to the
    architecture's display name for anything unrecognized."""
    import capstone
    a = arch.arch
    if a == capstone.CS_ARCH_X86:
        return 'x86_64' if arch.address_size == 8 else 'x86'
    if a == getattr(capstone, 'CS_ARCH_ARM64', getattr(capstone, 'CS_ARCH_AARCH64', None)):
        return 'aarch64'
    if a == getattr(capstone, 'CS_ARCH_RISCV', None):
        return 'riscv64'
    return arch.name


def _binary_arch_key(lib_item):
    """Canonical arch key ('x86' / 'x86_64' / 'aarch64' / 'riscv64') for a
    library item, resolved from its ELF/PE/Mach-O header only (no gadget scan).
    Returns None if the header can't be read or the arch is unrecognized."""
    try:
        import rop3.binary as _binary
        return _arch_key(_binary.Binary(lib_item['files'][0], None, None).get_arch())
    except Exception:
        return None


def _resolve_depth(lib_item, fallback):
    """Depth (bytes) for this binary: its architecture's entry in
    DEPTH_BY_ARCH, else the map's 'default', else `fallback`. A value of None
    means 'use the architecture's own default' (Rop3(depth=None)). Detecting
    the arch only parses the header (no gadget scan)."""
    if not DEPTH_BY_ARCH:
        return fallback
    key = _binary_arch_key(lib_item)
    if key in DEPTH_BY_ARCH:
        return DEPTH_BY_ARCH[key]
    return DEPTH_BY_ARCH.get('default', fallback)


def _single_ops_lib_worker(lib_item, single_ops, depth, jop, ropblock):
    lib_name = lib_item['name']
    results = {}
    # Cleared by any failure that says more about this run than about the
    # binary (OOM, an unexpected crash): those results must not be cached.
    cacheable = True

    try:
        from rop3.arch import arch_singleton
        from rop3.parser import OperationNotAvailable
        arch_singleton.reset()

        rop = _api_mod.Rop3(lib_item['files'],
                            depth=_resolve_depth(lib_item, depth),
                            rop=not jop,
                            jop=jop,
                            ropblock=ropblock,
                            **ROP3_KWARGS)
        rop.gadgets()

        for op_str in single_ops:
            try:
                results[op_str] = len(rop.find_op(op_str))
            except (OperationNotAvailable, NotImplementedError) as na:
                # Operation is not available for this architecture (e.g. RISC-V
                # has no carry/condition flags): count it as absent, not an error.
                print(f"  [n/a]   {lib_name} × {op_str}: unavailable for this architecture", file=sys.stderr)
                results[op_str] = 0
            except MemoryError:
                print(f"  [WARN] {lib_name} × {op_str}: Out of Memory", file=sys.stderr)
                results[op_str] = 0
                cacheable = False
            except Exception as exc:
                print(f"  [WARN] {lib_name} × {op_str}: {exc}", file=sys.stderr)
                results[op_str] = 0
                cacheable = False

    except MemoryError:
        print(f"  [FATAL] {lib_name}: Out of Memory during gadget extraction", file=sys.stderr)
        for op_str in single_ops:
            results[op_str] = 0
        cacheable = False
    except NotImplementedError as ni:
        # Architecture unsupported at load time (e.g. RV32): every op is absent.
        print(f"  [n/a]   {lib_name}: {ni}", file=sys.stderr)
        for op_str in single_ops:
            results[op_str] = 0
    except Exception as fatal_exc:
        print(f"  [FATAL] Failed to process {lib_name}: {fatal_exc}", file=sys.stderr)
        for op_str in single_ops:
            results[op_str] = 0
        cacheable = False

    finally:
        if 'rop' in locals(): del rop
        gc.collect()

    return lib_name, results, cacheable


def _presence_lib_worker(lib_item, single_ops, depth, jop, ropblock):
    """Gadget-presence probe for one binary (one architecture).

    Detects the binary's architecture and, for each operation, records how many
    matching gadgets exist (0 == absent). Operations that are not available for
    the architecture -- RISC-V has no carry/condition flags, so eqc/ltc raise
    OperationNotAvailable during YAML resolution, and unsupported ISAs raise
    NotImplementedError at load -- are caught and counted as zero rather than
    aborting the run. The detected architecture is returned under the reserved
    'arch' key so the caller can label the row.
    """
    lib_name = lib_item['name']
    results = {}
    arch_name = 'unknown'
    cacheable = True          # see _single_ops_lib_worker

    try:
        from rop3.arch import arch_singleton
        from rop3.parser import OperationNotAvailable
        arch_singleton.reset()

        rop = _api_mod.Rop3(lib_item['files'],
                            depth=_resolve_depth(lib_item, depth),
                            rop=not jop,
                            jop=jop,
                            ropblock=ropblock,
                            **ROP3_KWARGS)
        rop.gadgets()
        arch_name = arch_singleton.arch.name

        for op_str in single_ops:
            try:
                results[op_str] = len(rop.find_op(op_str))
            except (OperationNotAvailable, NotImplementedError):
                # Operation not available for this architecture -> absent.
                print(f"  [n/a]   {lib_name} ({arch_name}) × {op_str}: unavailable for this architecture", file=sys.stderr)
                results[op_str] = 0
            except MemoryError:
                print(f"  [WARN] {lib_name} × {op_str}: Out of Memory", file=sys.stderr)
                results[op_str] = 0
                cacheable = False
            except Exception as exc:
                print(f"  [WARN] {lib_name} × {op_str}: {exc}", file=sys.stderr)
                results[op_str] = 0
                cacheable = False

    except MemoryError:
        print(f"  [FATAL] {lib_name}: Out of Memory during gadget extraction", file=sys.stderr)
        for op_str in single_ops:
            results[op_str] = 0
        cacheable = False
    except NotImplementedError as ni:
        # Architecture unsupported at load time (e.g. RV32): everything absent.
        print(f"  [n/a]   {lib_name}: {ni}", file=sys.stderr)
        arch_name = 'unsupported'
        for op_str in single_ops:
            results[op_str] = 0
    except Exception as fatal_exc:
        print(f"  [FATAL] Failed to process {lib_name}: {fatal_exc}", file=sys.stderr)
        for op_str in single_ops:
            results[op_str] = 0
        cacheable = False

    finally:
        if 'rop' in locals(): del rop
        gc.collect()

    results['arch'] = arch_name
    return lib_name, results, cacheable


def _ropchains_lib_worker(lib_item, ropchain_files, depth, jop, ropblock):
    """Benchmark ROP-chain search for one binary.

    Returns (lib_name, payload, cacheable) where payload is
        {'arch': <display name>, 'extract_seconds': <float|None>,
         'chains': [{'chain': <basename>, 'found': bool,
                     'seconds': <float|None>, 'status': <str>}, ...]}
    Only chains whose target architecture matches the binary are run (a chain
    whose arch can't be inferred from its name is run against every binary);
    arch-mismatched chains are logged as `[skip]` and produce no row. `seconds`
    times the search only -- gadget extraction is the shared per-binary cost
    reported once as `extract_seconds`. `status` is one of found / not-found /
    timeout / error / fatal (the last when gadget extraction itself failed)."""
    lib_name  = lib_item['name']
    arch_key  = _binary_arch_key(lib_item)

    matched, skipped = [], []
    for rc_file in ropchain_files:
        ca = _chain_arch(rc_file)
        if ca is not None and arch_key is not None and ca != arch_key:
            skipped.append(rc_file)
        else:
            matched.append(rc_file)
    for rc_file in skipped:
        print(f"    [skip] {lib_name} ({arch_key or '?'}) × {os.path.basename(rc_file)}: "
              f"targets {_chain_arch(rc_file)}", file=sys.stderr)

    chains = []
    try:
        from rop3.arch import arch_singleton
        arch_singleton.reset()

        rop = _api_mod.Rop3(lib_item['files'], depth=_resolve_depth(lib_item, depth), rop=not jop, jop=jop, ropblock=ropblock, **ROP3_KWARGS)
        t0 = time.perf_counter()
        rop.gadgets()
        extract_seconds = time.perf_counter() - t0
        arch_name = arch_singleton.arch.name

        for rc_file in matched:
            chain_name = os.path.basename(rc_file)
            if CHAIN_TIMEOUT:
                signal.signal(signal.SIGALRM, _alarm_handler)
                signal.setitimer(signal.ITIMER_REAL, CHAIN_TIMEOUT)
            t = time.perf_counter()
            try:
                next(rop.ropchain(rc_file))
                found, status = True, 'found'
            except (_ropchain_mod.RopChainNotFound, StopIteration):
                found, status = False, 'not-found'
            except _ChainTimeout:
                found, status = False, 'timeout'
                print(f"  [WARN] {lib_name} × {chain_name}: timed out after {CHAIN_TIMEOUT}s", file=sys.stderr)
            except MemoryError:
                found, status = False, 'error'
                print(f"  [WARN] {lib_name} × {chain_name}: Out of Memory", file=sys.stderr)
            except Exception as exc:
                found, status = False, 'error'
                print(f"  [WARN] {lib_name} × {chain_name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            finally:
                if CHAIN_TIMEOUT:
                    signal.setitimer(signal.ITIMER_REAL, 0)
            seconds = round(time.perf_counter() - t, 4)
            chains.append({'chain': chain_name, 'found': found,
                           'seconds': seconds, 'status': status})

        # A timeout is a real, reproducible outcome under the same chain_timeout
        # (and the most expensive one to repeat), so it stays cacheable; an
        # 'error' is environmental (OOM, an engine crash) and is not.
        cacheable = not any(c['status'] == 'error' for c in chains)
        return lib_name, {'arch': arch_name, 'extract_seconds': round(extract_seconds, 4),
                          'chains': chains}, cacheable

    except MemoryError:
        print(f"  [FATAL] {lib_name}: Out of Memory during gadget extraction", file=sys.stderr)
        status = 'fatal'
    except Exception as fatal_exc:
        print(f"  [FATAL] Failed to process {lib_name}: {fatal_exc}", file=sys.stderr)
        status = 'fatal'
    finally:
        if 'rop' in locals(): del rop
        gc.collect()

    # Gadget extraction failed: emit one 'fatal' row per matched chain so the
    # pair still appears (search never ran, hence seconds/extract unknown).
    chains = [{'chain': os.path.basename(f), 'found': False,
               'seconds': None, 'status': status} for f in matched]
    return lib_name, {'arch': arch_key or 'unknown', 'extract_seconds': None,
                      'chains': chains}, False

class MatrixCollector:
    """Collector for the wide count matrices (ops / presence modes): each
    worker result maps operation -> count and is written straight into a
    per-library row of the DataFrame, checkpointed to TSV after every library."""

    def __init__(self, df, out_file):
        self.df = df
        self.out_file = out_file

    def add(self, lib_name, results):
        for item_name, value in results.items():
            self.df.at[lib_name, item_name] = value
            if item_name == 'arch':
                print(f"    ->  {lib_name}: arch = {value}", flush=True)
            else:
                print(f"    -  {lib_name}  ×  {item_name}: {value} gadgets", flush=True)

    def save(self):
        self.df.to_csv(self.out_file, sep="\t")


class RopchainRowCollector:
    """Collector for the ropchain benchmark: accumulates one row per
    (binary, chain) pair and writes a long-format TSV, checkpointed after every
    library. Arch-mismatched pairs never reach here (they produce no row)."""

    COLUMNS = ['library', 'arch', 'chain', 'found', 'seconds', 'extract_seconds', 'status']

    def __init__(self, out_file):
        self.out_file = out_file
        self.rows = []

    def add(self, lib_name, payload):
        arch    = payload.get('arch', 'unknown')
        extract = payload.get('extract_seconds')
        for c in payload.get('chains', []):
            self.rows.append({
                'library': lib_name, 'arch': arch, 'chain': c['chain'],
                'found': c['found'], 'seconds': c['seconds'],
                'extract_seconds': extract, 'status': c['status'],
            })
            mark = "✓" if c['found'] else "✗"
            secs = "n/a" if c['seconds'] is None else f"{c['seconds']:.2f}s"
            print(f"    {mark}  {lib_name}  ×  {c['chain']}: {c['status']} ({secs})", flush=True)

    def save(self):
        df = pd.DataFrame(self.rows, columns=self.COLUMNS)
        if not df.empty:
            df = df.sort_values(['library', 'chain']).reset_index(drop=True)
        df.to_csv(self.out_file, sep="\t", index=False)

    def summary(self, total_pairs):
        """(found, matched, skipped) counts. `matched` = pairs that were run
        (one row each); `skipped` = arch-mismatched pairs that produced no row."""
        found   = sum(1 for r in self.rows if r['found'])
        matched = len(self.rows)
        skipped = total_pairs - matched
        return found, matched, skipped


def _make_cache(items_to_test, mode):
    """Build this run's result cache, or None when it is off or unusable.

    Stored in the CACHE global because run_tasks() reads its settings the same
    way it reads WORKERS/SEQUENTIAL. Anything missing -- helpers, a machine id,
    the rop3 commit -- downgrades to "no cache" with a warning: a slow run is
    always better than a wrong one.
    """
    global CACHE
    CACHE = None
    if not CACHE_ENABLED or benchcache is None:
        return None

    if not ROP3_COMMIT:
        print("[WARN] rop3 commit unknown (not a git checkout?): running without "
              "the result cache", file=sys.stderr)
        return None

    machine = (MACHINE or {}).get('id') or (machine_specs.machine_id() if machine_specs else None)
    if not machine:
        print("[WARN] machine id unknown: running without the result cache",
              file=sys.stderr)
        return None

    CACHE = benchcache.Cache(
        CACHE_DIR or benchcache.DEFAULT_CACHE_DIR,
        machine=str(machine),
        commit=ROP3_COMMIT,
        cfg_hash=benchcache.config_hash(CONFIG, mode),
        items=benchcache.fingerprint_items(items_to_test),
        mode=mode,
        read=not CACHE_REFRESH,
        write=True,
    )
    note = " [--refresh-cache: re-measuring everything]" if CACHE_REFRESH else ""
    print(f"Cache {CACHE.dir} — {CACHE.describe()}{note}")
    return CACHE


def _write_run_meta(mode, out_file, elapsed, total_libs, path="run-meta.yaml"):
    """Record which machine and which rop3 produced out_file, next to it.

    Written into the current directory, which experiments/run_all.py sets to
    results/<experiment>/ -- so the provenance is committed alongside the TSV
    and picked up by utils/build_site.py. YAML rather than TSV on purpose:
    build_site.py globs *.tsv and would render a sidecar as a results card.
    """
    import datetime
    meta = {
        'generated':       datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
        'results':         out_file,
        'mode':            mode,
        'experiment':      CONFIG.get('name'),
        # experiments/run_all.py feeds the driver a rewritten temp copy of the
        # config, so this basename carries the experiment stem plus noise; the
        # `experiment` title above is the readable one.
        'config':          os.path.basename(CONFIG_PATH) if CONFIG_PATH else None,
        'config_hash':     benchcache.config_hash(CONFIG, mode) if benchcache else None,
        'rop3_commit':     ROP3_COMMIT,
        'elapsed_seconds': round(elapsed, 2),
        'libraries':       total_libs,
        'reused_from_cache': CACHE.hits if CACHE is not None else 0,
        'workers':         1 if SEQUENTIAL else WORKERS,
        'sequential':      bool(SEQUENTIAL),
        'machine':         MACHINE,
    }
    try:
        with open(path, 'w') as f:
            if machine_specs is not None:
                machine_specs.dump_yaml(meta, f)
            else:
                import yaml
                yaml.safe_dump(meta, f, sort_keys=False, allow_unicode=True)
    except Exception as exc:
        print(f"[WARN] could not write {path}: {exc}", file=sys.stderr)
        return
    print(f"Run metadata saved to {path!r}")


def run_tasks(libs, items_to_test, worker_func, collector):
    total_libs = len(libs)
    total_items = len(items_to_test)
    total_combinations = total_libs * total_items
    done_libs = 0

    print(
        f"Checking {total_libs} librar{'y' if total_libs == 1 else 'ies'} "
        f"× {total_items} task(s) = {total_combinations} combinations "
        f"[{'sequential' if SEQUENTIAL else f'{WORKERS} workers'}]"
    )

    # Replay whatever this machine already measured under the same conditions,
    # then run only what is left. Cached libraries go through the collector
    # like any other result, so the progress counter and the ropchains pair
    # arithmetic stay honest.
    pending = libs
    if CACHE is not None:
        pending = []
        for lib in libs:
            payload = CACHE.get(lib['name'])
            if payload is None:
                pending.append(lib)
                continue
            collector.add(lib['name'], payload)
            done_libs += 1
            print(f"  [cache] {lib['name']}: reusing previous result "
                  f"[{done_libs}/{total_libs}]", flush=True)
        if done_libs:
            collector.save()
        if not pending:
            print("  Everything served from the cache; nothing to run.")
            return

    if SEQUENTIAL:
        global _api_mod, _ropchain_mod
        # Pool workers get this cap in _worker_init; in sequential mode the scan
        # runs in this very process, so apply it here too or a huge binary can
        # OOM-kill the whole run instead of raising a catchable MemoryError.
        _apply_memory_limit()
        import rop3.api      as api
        import rop3.ropchain as ropchain
        _api_mod      = api
        _ropchain_mod = ropchain

        for lib in pending:
            lib_name, results, cacheable = worker_func(lib, items_to_test, GADFINDER_DEPTH, JOP, ROPBLOCK)
            if CACHE is not None and cacheable:
                CACHE.put(lib_name, results)
            collector.add(lib_name, results)
            done_libs += 1
            print(f"  [{done_libs}/{total_libs} libraries complete] → checkpoint saved", flush=True)
            collector.save()
    else:
        with ProcessPoolExecutor(
            max_workers=WORKERS,
            initializer=_worker_init,
            initargs=(ROP3_FOLDER, ROP3_KWARGS, DEPTH_BY_ARCH, CHAIN_TIMEOUT)
        ) as pool:
            futures = {
                pool.submit(worker_func, lib, items_to_test, GADFINDER_DEPTH, JOP, ROPBLOCK): lib
                for lib in pending
            }

            for fut in as_completed(futures):
                lib = futures[fut]
                try:
                    lib_name, results, cacheable = fut.result()
                    if CACHE is not None and cacheable:
                        CACHE.put(lib_name, results)
                    collector.add(lib_name, results)
                except Exception as exc:
                    print(f"  [ERROR] Worker crashed processing {lib['name']}: {exc}", file=sys.stderr)

                done_libs += 1
                print(f"  [{done_libs}/{total_libs} libraries complete] → checkpoint saved", flush=True)
                collector.save()

def get_single_ops():
    if JOP:
        return JOP_GADGETS
    else:
        return ROP_GADGETS

def _scan_lib_folder(path):
    items = []                                                              
    extensions = ['*.so*', '*.dylib', '*.dll', "*_bin"]                              
    for ext in extensions:                                                  
        for f in glob.glob(os.path.join(path, ext)):  
            file_size_mb = round(os.path.getsize(f) / (1024 * 1024), 2)
            items.append({'name': os.path.basename(f), 'files': [f], 'size_mb': file_size_mb})
            
    # Every subdirectory is a bundle (its files scanned together as one target).
    for bundle in pathlib.Path(path).iterdir():
        if bundle.is_dir() and not bundle.name.startswith('.'):
            bundle_files = [str(f) for f in bundle.iterdir() if f.is_file()]
            bundle_size_bytes = sum(os.path.getsize(f) for f in bundle_files)
            bundle_size_mb = round(bundle_size_bytes / (1024 * 1024), 2)
            items.append({'name': bundle.name, 'files': bundle_files, 'size_mb': bundle_size_mb})

    return items


def _lib_item(path):
    size_mb = round(os.path.getsize(path) / (1024 * 1024), 2)
    return {'name': os.path.basename(path), 'files': [path], 'size_mb': size_mb}


def get_libs(spec):
    """Resolve a library spec into lib items. `spec` may be a folder (scanned
    for *.so*/*.dylib/*.dll/*_bin plus a bundle per subfolder), a single file, a
    glob, or a list mixing any of those (as allowed in the YAML config's 'libraries')."""
    if isinstance(spec, (list, tuple)):
        items = []
        for entry in spec:
            items.extend(get_libs(entry))
        return items
    if os.path.isdir(spec):
        return _scan_lib_folder(spec)
    if os.path.isfile(spec):
        return [_lib_item(spec)]
    if any(ch in str(spec) for ch in '*?['):
        return [_lib_item(f) for f in sorted(glob.glob(spec)) if os.path.isfile(f)]
    return []


def _spec_label(spec):
    """Short label for output filenames, derived from the library spec."""
    if isinstance(spec, (list, tuple)):
        return 'libs'
    return os.path.basename(os.path.normpath(str(spec)))


def load_config(path):
    """Load the YAML scan-parameters config into a dict."""
    import yaml
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    if not isinstance(cfg, dict):
        print(f"ERROR: config {path!r} must be a YAML mapping.", file=sys.stderr)
        sys.exit(1)
    return cfg


_CHAIN_ARCH_TOKENS = {
    'amd64': 'x86_64', 'x86_64': 'x86_64', 'x64': 'x86_64',
    'x86': 'x86', 'i386': 'x86', 'i686': 'x86',
    'aarch64': 'aarch64', 'arm64': 'aarch64',
    'riscv': 'riscv64', 'riscv64': 'riscv64', 'rv64': 'riscv64',
}


def _chain_arch(path):
    """Canonical arch a ropchain file targets, inferred from its filename tokens
    (e.g. 'syscall_exec_amd64.txt' -> 'x86_64'). Returns None when no token is
    recognized; such a chain is treated as arch-agnostic and run against every
    binary, so a differently-named chain is never silently dropped."""
    stem = os.path.splitext(os.path.basename(path))[0].lower()
    for token in stem.replace('-', '_').split('_'):
        if token in _CHAIN_ARCH_TOKENS:
            return _CHAIN_ARCH_TOKENS[token]
    return None


def get_ropchain_files(ropchains_folder):
    files = []
    extensions = ['*.txt', '*.rop']
    for ext in extensions:
        files.extend(glob.glob(os.path.join(ropchains_folder, ext)))
        
    if not files:
        files = [str(p) for p in pathlib.Path(ropchains_folder).iterdir() if p.is_file()]
        
    valid_files = [
        f for f in files 
        if os.path.isfile(f) and not os.path.basename(f).startswith('.')
    ]
    return sorted(valid_files)

def main(lib_folder):
    t1 = time.time()
    single_ops = get_single_ops()
    libs       = get_libs(lib_folder)
    
    if not libs:
        print("ERROR: No libraries found.", file=sys.stderr)
        sys.exit(1)

    out_file = "results"
    if JOP:
        out_file += "_jop"
    elif ROPBLOCK:
        out_file += "_ropblock"
    else:
        out_file += "_rop"
    out_file += f"_{_spec_label(lib_folder)}.tsv"
    df = pd.DataFrame(index=[item['name'] for item in libs], columns=single_ops)
    df.index.name = "library"
    df.columns.name = "operation"
    collector = MatrixCollector(df, out_file)
    collector.save()
    _make_cache(single_ops, 'ops')

    try:
        run_tasks(libs, single_ops, _single_ops_lib_worker, collector)
    except KeyboardInterrupt:
        print("\nInterrupted — saving partial results …", file=sys.stderr)
        collector.save()

    print(f"\nSaved to {out_file!r}")
    print(f"Completed in {time.time() - t1:.2f} seconds")
    _write_run_meta('ops', out_file, time.time() - t1, len(libs))


def main_presence(lib_folder):
    """Test gadget presence across architectures.

    Point this at a folder holding binaries of different architectures (e.g.
    examples/ with libc for x86/amd64/riscv64/aarch64). For every binary it
    detects the architecture and records, per operation, how many gadgets
    realize it (0 == absent). Operations unavailable for an architecture are
    counted as zero (see _presence_lib_worker), so the resulting matrix shows
    which operations each ISA can supply.
    """
    t1 = time.time()
    single_ops = get_single_ops()
    libs       = get_libs(lib_folder)

    if not libs:
        print("ERROR: No libraries found.", file=sys.stderr)
        sys.exit(1)

    out_file = "results_presence_"
    out_file += "jop" if JOP else ("ropblock" if ROPBLOCK else "rop")
    out_file += f"_{_spec_label(lib_folder)}.tsv"

    # 'arch' (detected per binary) precedes the operation columns.
    df = pd.DataFrame(index=[item['name'] for item in libs],
                      columns=['arch'] + single_ops)
    df.index.name = "library"
    df.columns.name = "operation"
    collector = MatrixCollector(df, out_file)
    collector.save()
    _make_cache(single_ops, 'presence')

    try:
        run_tasks(libs, single_ops, _presence_lib_worker, collector)
    except KeyboardInterrupt:
        print("\nInterrupted — saving partial results …", file=sys.stderr)
        collector.save()

    print(f"\nGadget presence by architecture:")
    print(df.to_string())
    print(f"\nSaved to {out_file!r}")
    print(f"Completed in {time.time() - t1:.2f} seconds")
    _write_run_meta('presence', out_file, time.time() - t1, len(libs))


def main_ropchains(lib_folder, ropchains_folder):
    t1 = time.time()
    libs           = get_libs(lib_folder)
    ropchain_files = get_ropchain_files(ropchains_folder)

    if not libs:
        print("ERROR: No libraries found.", file=sys.stderr)
        sys.exit(1)
    if not ropchain_files:
        print("ERROR: No ropchain files found.", file=sys.stderr)
        sys.exit(1)

    out_file = ("results_ropchains_jop.tsv" if JOP
                else "results_ropchains_ropblock.tsv" if ROPBLOCK
                else "results_ropchains_rop.tsv")

    collector = RopchainRowCollector(out_file)
    collector.save()   # write the header immediately so the checkpoint exists
    _make_cache(ropchain_files, 'ropchains')

    try:
        run_tasks(libs, ropchain_files, _ropchains_lib_worker, collector)
    except KeyboardInterrupt:
        print("\nInterrupted — saving partial results …", file=sys.stderr)
        collector.save()

    total_pairs = len(libs) * len(ropchain_files)
    found, matched, skipped = collector.summary(total_pairs)
    print(f"\nResults ({found}/{matched} arch-matched pairs realizable; "
          f"{skipped} pair(s) skipped for arch mismatch):")
    if collector.rows:
        df = pd.DataFrame(collector.rows, columns=RopchainRowCollector.COLUMNS)
        print(df.sort_values(['library', 'chain']).to_string(index=False))
    print(f"\nSaved to {out_file!r}")
    print(f"Completed in {time.time() - t1:.2f} seconds")
    _write_run_meta('ropchains', out_file, time.time() - t1, len(libs))


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(
        description="Analyse ROP/JOP gadget coverage of binary libraries. "
                    "Scan parameters (libraries, per-architecture depth, Rop3 "
                    "flags, ...) may be set in a YAML config via --config; any "
                    "command-line option overrides the config."
    )
    # Positionals are optional: they may instead come from the config file.
    arg_parser.add_argument(
        'rop3', type=str, nargs='?', default=None,
        help="rop3 project folder (must contain rop3.py). Config key: 'rop3'. "
             "Defaults to the bundled ./rop3 submodule beside this script.",
    )
    arg_parser.add_argument(
        'libs', type=str, nargs='?', default=None,
        help="folder/file/glob of libraries (each subfolder is a bundle). Config key: 'libraries'.",
    )
    arg_parser.add_argument(
        '--config', type=str, metavar='FILE', required=True,
        help='YAML config file of scan parameters (required). See template.yaml '
             'for reference. CLI options override it.',
    )
    # For the options below, a None default means "unset on the command line",
    # so the config value (then the built-in default) is used.
    arg_parser.add_argument(
        '--jop', action=argparse.BooleanOptionalAction, default=None,
        help='search for JOP gadgets instead of ROP gadgets',
    )
    arg_parser.add_argument(
        '--ropblock', action=argparse.BooleanOptionalAction, default=None,
        help='search for ROPBLOCK gadgets',
    )
    arg_parser.add_argument(
        '--ropchains', type=str, metavar='DIR', default=None,
        help='directory of ropchain files (.rop or .txt). Produces a long-format '
             'benchmark table (one row per arch-matched binary×chain pair, with '
             'found/seconds). Config key: mode: ropchains + ropchains: <dir>.',
    )
    arg_parser.add_argument(
        '--chain-timeout', type=float, default=None, metavar='SECONDS',
        help='per-chain search timeout for ropchains mode (0/unset = unlimited). '
             "Config key: 'chain_timeout'.",
    )
    arg_parser.add_argument(
        '--presence', action='store_true', default=None,
        help='test gadget presence across architectures: point --libs at binaries of '
             'different archs (e.g. examples/) to get an arch x operation matrix. '
             'Operations unavailable for an arch are counted as zero. '
             "Config: mode: presence.",
    )
    arg_parser.add_argument(
        '--sequential', action='store_true', default=None,
        help='run tasks one at a time in the main process instead of using worker subprocesses.',
    )
    arg_parser.add_argument(
        '--workers', type=int, default=None, metavar='N',
        help='number of parallel worker processes (default: 4; ignored with --sequential)',
    )
    arg_parser.add_argument(
        '--no-cache', action='store_true', default=False,
        help='do not read or write the per-library result cache (see '
             "utils/benchcache.py). Config key: 'cache: false'.",
    )
    arg_parser.add_argument(
        '--refresh-cache', action='store_true', default=False,
        help='re-measure every library, overwriting its cache entry instead of '
             'reusing it. Use after changing the binaries under a libraries folder.',
    )
    arg_parser.add_argument(
        '--cache-dir', type=str, default=None, metavar='DIR',
        help="result cache directory (default: .benchcache/ beside this script; "
             "a relative path is taken from there too). Config key: 'cache_dir'.",
    )
    arg_parser.add_argument(
        '--depth', type=int, default=None, metavar='N',
        help='override the search depth in bytes for ALL architectures. Without it, '
             "the config's per-architecture 'depth' map is used (default: 10; with "
             "--presence, each architecture's own default).",
    )

    args = arg_parser.parse_args(sys.argv[1:])

    # --- Load config (required via --config) ---------------------------------
    config_path = args.config
    if not os.path.isfile(config_path):
        print(f"ERROR: config file not found: {config_path!r}", file=sys.stderr)
        sys.exit(1)
    config = load_config(config_path)
    print(f"Using config {config_path!r}")

    # --- Resolve settings: CLI overrides config overrides built-in defaults ---
    rop3_folder = args.rop3 or config.get('rop3') or DEFAULT_ROP3_FOLDER
    libs_spec   = args.libs or config.get('libraries')
    if not libs_spec:
        print("ERROR: libraries not given (positional or config 'libraries').",
              file=sys.stderr)
        sys.exit(1)

    prepare_env(rop3_folder)

    ROP3_FOLDER = rop3_folder
    JOP        = args.jop        if args.jop        is not None else bool(config.get('jop', False))
    ROPBLOCK   = args.ropblock   if args.ropblock   is not None else bool(config.get('ropblock', False))
    SEQUENTIAL = args.sequential if args.sequential is not None else bool(config.get('sequential', False))
    WORKERS    = args.workers    if args.workers    is not None else int(config.get('workers', 4))

    # --- Provenance + result cache ------------------------------------------
    CONFIG_PATH   = config_path
    CACHE_ENABLED = (not args.no_cache) and bool(config.get('cache', True))
    CACHE_REFRESH = bool(args.refresh_cache)
    _cache_dir    = args.cache_dir or config.get('cache_dir')
    if _cache_dir and not os.path.isabs(_cache_dir):
        # Relative to this script, not to the cwd: experiments/run_all.py runs
        # every config from its own results/<name>/ directory, and one cache
        # per experiment would defeat the point.
        _cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), _cache_dir)
    CACHE_DIR     = _cache_dir
    MACHINE       = machine_specs.load() if machine_specs else None
    ROP3_COMMIT   = benchcache.rop3_commit(rop3_folder) if benchcache else None
    ropchains  = args.ropchains  or config.get('ropchains')
    mode       = str(config.get('mode', '')).lower()
    presence   = args.presence   if args.presence   is not None \
        else (mode == 'presence')

    # `mode: ropchains` needs a chain directory; dispatch keys off that path, so
    # a missing 'ropchains:' would otherwise fall through silently to ops mode.
    if mode == 'ropchains' and not ropchains:
        print("ERROR: mode: ropchains requires a 'ropchains' directory key "
              "(or --ropchains DIR).", file=sys.stderr)
        sys.exit(1)

    # Per-chain search timeout (ropchains mode); 0 or unset means unlimited.
    _ct = args.chain_timeout if args.chain_timeout is not None else config.get('chain_timeout')
    CHAIN_TIMEOUT = float(_ct) if _ct else None

    # Rop3 flag kwargs passed straight to the Rop3 constructor.
    ROP3_KWARGS = dict(config.get('rop3_flags') or DEFAULT_ROP3_FLAGS)

    # ropblock is inherently a *framed* search (its terminator branches through a
    # stack-restored register) and the --ropblock scan ignores `framed`. Running
    # it with framed:false yields an unframed ROP baseline that, on AArch64/RISC-V,
    # counts non-chainable `ret`-gadgets whose return address is never reloaded
    # from the stack -- making ropblock look like it under-detects. Warn so the
    # comparison stays framed-to-framed.
    if ROPBLOCK and ROP3_KWARGS.get('framed') is False:
        print("  [WARN] framed=false with --ropblock: the ROP baseline will be "
              "UNframed and not comparable to ropblock on AArch64/RISC-V "
              "(ropblock is inherently framed). Use framed=true for a fair "
              "ropblock-vs-ROP comparison.", file=sys.stderr)

    # Operation lists (optional override).
    _ops = config.get('operations') or {}
    if _ops.get('rop'):
        ROP_GADGETS = list(_ops['rop'])
    if _ops.get('jop'):
        JOP_GADGETS = list(_ops['jop'])

    # Depth: an explicit --depth applies to every architecture; otherwise use
    # the config's per-architecture map. The fallback (for archs absent from the
    # map, or when there is no map) is the architecture's own default (None) in
    # presence mode, else the historical 10.
    if args.depth is not None:
        DEPTH_BY_ARCH = {}
        GADFINDER_DEPTH = args.depth
    else:
        DEPTH_BY_ARCH = dict(config.get('depth') or {})
        GADFINDER_DEPTH = DEPTH_BY_ARCH.get('default', None)
        if GADFINDER_DEPTH is None and not presence:
            GADFINDER_DEPTH = 10

    # Hash the *resolved* settings rather than the file on disk: --jop, --depth,
    # --chain-timeout and friends change the results without changing the YAML,
    # and a cache key that ignored them would hand back the wrong answer.
    CONFIG = dict(config)
    CONFIG.update({
        'jop':           JOP,
        'ropblock':      ROPBLOCK,
        'workers':       WORKERS,
        'sequential':    SEQUENTIAL,
        'chain_timeout': CHAIN_TIMEOUT,
        'depth':         dict(DEPTH_BY_ARCH) if DEPTH_BY_ARCH else {'default': GADFINDER_DEPTH},
        'rop3_flags':    dict(ROP3_KWARGS),
        'operations':    {'rop': list(ROP_GADGETS), 'jop': list(JOP_GADGETS)},
    })

    if ropchains:
        main_ropchains(libs_spec, ropchains)
    elif presence:
        main_presence(libs_spec)
    else:
        main(libs_spec)

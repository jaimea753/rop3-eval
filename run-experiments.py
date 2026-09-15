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

def _worker_init(rop3_folder, rop3_kwargs, depth_by_arch):
    """Initializes the worker process, setting memory limits and loading rop3."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    if HAS_RESOURCE:
        max_mem_bytes = 16 * 1024 * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_AS, (max_mem_bytes, max_mem_bytes))
        except Exception as e:
            print(f"  [WARN] Could not set memory limit: {e}", file=sys.stderr)

    global _api_mod, _ropchain_mod, ROP3_KWARGS, DEPTH_BY_ARCH
    ROP3_KWARGS   = rop3_kwargs
    DEPTH_BY_ARCH = depth_by_arch
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


def _resolve_depth(lib_item, fallback):
    """Depth (bytes) for this binary: its architecture's entry in
    DEPTH_BY_ARCH, else the map's 'default', else `fallback`. A value of None
    means 'use the architecture's own default' (Rop3(depth=None)). Detecting
    the arch only parses the header (no gadget scan)."""
    if not DEPTH_BY_ARCH:
        return fallback
    key = None
    try:
        import rop3.binary as _binary
        key = _arch_key(_binary.Binary(lib_item['files'][0], None, None).get_arch())
    except Exception:
        pass
    if key in DEPTH_BY_ARCH:
        return DEPTH_BY_ARCH[key]
    return DEPTH_BY_ARCH.get('default', fallback)


def _single_ops_lib_worker(lib_item, single_ops, depth, jop, ropblock):
    lib_name = lib_item['name']
    results = {}

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
            except Exception as exc:
                print(f"  [WARN] {lib_name} × {op_str}: {exc}", file=sys.stderr)
                results[op_str] = 0

    except MemoryError:
        print(f"  [FATAL] {lib_name}: Out of Memory during gadget extraction", file=sys.stderr)
        for op_str in single_ops:
            results[op_str] = 0
    except NotImplementedError as ni:
        # Architecture unsupported at load time (e.g. RV32): every op is absent.
        print(f"  [n/a]   {lib_name}: {ni}", file=sys.stderr)
        for op_str in single_ops:
            results[op_str] = 0
    except Exception as fatal_exc:
        print(f"  [FATAL] Failed to process {lib_name}: {fatal_exc}", file=sys.stderr)
        for op_str in single_ops:
            results[op_str] = 0

    finally:
        if 'rop' in locals(): del rop
        gc.collect()

    return lib_name, results


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
            except Exception as exc:
                print(f"  [WARN] {lib_name} × {op_str}: {exc}", file=sys.stderr)
                results[op_str] = 0

    except MemoryError:
        print(f"  [FATAL] {lib_name}: Out of Memory during gadget extraction", file=sys.stderr)
        for op_str in single_ops:
            results[op_str] = 0
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

    finally:
        if 'rop' in locals(): del rop
        gc.collect()

    results['arch'] = arch_name
    return lib_name, results


def _ropchains_lib_worker(lib_item, ropchain_files, depth, jop, ropblock):
    lib_name = lib_item['name']
    results = {}

    try:
        from rop3.arch import arch_singleton
        arch_singleton.reset()

        rop = _api_mod.Rop3(lib_item['files'], depth=_resolve_depth(lib_item, depth), rop=not jop, jop=jop, ropblock=ropblock, **ROP3_KWARGS)
        rop.gadgets()

        for rc_file in ropchain_files:
            chain_name = os.path.basename(rc_file)
            try:
                next(rop.ropchain(rc_file))
                results[chain_name] = True
            except (_ropchain_mod.RopChainNotFound, StopIteration):
                results[chain_name] = False
            except MemoryError:
                print(f"  [WARN] {lib_name} × {chain_name}: Out of Memory", file=sys.stderr)
                results[chain_name] = False
            except Exception as exc:
                print(f"  [WARN] {lib_name} × {chain_name}: {type(exc).__name__}: {exc}", file=sys.stderr)
                results[chain_name] = False

    except MemoryError:
        print(f"  [FATAL] {lib_name}: Out of Memory during gadget extraction", file=sys.stderr)
        for rc_file in ropchain_files:
            results[os.path.basename(rc_file)] = False
    except Exception as fatal_exc:
        print(f"  [FATAL] Failed to process {lib_name}: {fatal_exc}", file=sys.stderr)
        for rc_file in ropchain_files:
            results[os.path.basename(rc_file)] = False

    finally:
        if 'rop' in locals(): del rop
        gc.collect()

    return lib_name, results

def run_tasks(libs, items_to_test, worker_func, df, out_file, is_ropchain=False):
    total_libs = len(libs)
    total_items = len(items_to_test)
    total_combinations = total_libs * total_items
    done_libs = 0

    print(
        f"Checking {total_libs} librar{'y' if total_libs == 1 else 'ies'} "
        f"× {total_items} task(s) = {total_combinations} combinations "
        f"[{'sequential' if SEQUENTIAL else f'{WORKERS} workers'}]"
    )

    if SEQUENTIAL:
        global _api_mod, _ropchain_mod
        import rop3.api      as api
        import rop3.ropchain as ropchain
        _api_mod      = api
        _ropchain_mod = ropchain

        for lib in libs:
            lib_name, results = worker_func(lib, items_to_test, GADFINDER_DEPTH, JOP, ROPBLOCK)
            _process_worker_results(lib_name, results, df, is_ropchain)
            done_libs += 1
            print(f"  [{done_libs}/{total_libs} libraries complete] → checkpoint saved", flush=True)
            df.to_csv(out_file, sep="\t")
    else:
        with ProcessPoolExecutor(
            max_workers=WORKERS,
            initializer=_worker_init,
            initargs=(ROP3_FOLDER, ROP3_KWARGS, DEPTH_BY_ARCH)
        ) as pool:
            futures = {
                pool.submit(worker_func, lib, items_to_test, GADFINDER_DEPTH, JOP, ROPBLOCK): lib
                for lib in libs
            }
            
            for fut in as_completed(futures):
                lib = futures[fut]
                try:
                    lib_name, results = fut.result()
                    _process_worker_results(lib_name, results, df, is_ropchain)
                except Exception as exc:
                    print(f"  [ERROR] Worker crashed processing {lib['name']}: {exc}", file=sys.stderr)
                
                done_libs += 1
                print(f"  [{done_libs}/{total_libs} libraries complete] → checkpoint saved", flush=True)
                df.to_csv(out_file, sep="\t")


def _process_worker_results(lib_name, results, df, is_ropchain):
    """Helper to update the DataFrame and print individual combination logs."""
    for item_name, value in results.items():
        df.at[lib_name, item_name] = value
        if item_name == 'arch':
            print(f"    ->  {lib_name}: arch = {value}", flush=True)
        elif is_ropchain:
            status = "✓" if value else "✗"
            print(f"    {status}  {lib_name}  ×  {item_name}", flush=True)
        else:
            print(f"    -  {lib_name}  ×  {item_name}: {value} gadgets", flush=True)

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
    df.to_csv(out_file, sep="\t")

    try:
        run_tasks(libs, single_ops, _single_ops_lib_worker, df, out_file, is_ropchain=False)
    except KeyboardInterrupt:
        print("\nInterrupted — saving partial results …", file=sys.stderr)
        df.to_csv(out_file, sep="\t")

    print(f"\nSaved to {out_file!r}")
    print(f"Completed in {time.time() - t1:.2f} seconds")


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
    df.to_csv(out_file, sep="\t")

    try:
        run_tasks(libs, single_ops, _presence_lib_worker, df, out_file, is_ropchain=False)
    except KeyboardInterrupt:
        print("\nInterrupted — saving partial results …", file=sys.stderr)
        df.to_csv(out_file, sep="\t")

    print(f"\nGadget presence by architecture:")
    print(df.to_string())
    print(f"\nSaved to {out_file!r}")
    print(f"Completed in {time.time() - t1:.2f} seconds")


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

    chain_names = [os.path.basename(f) for f in ropchain_files]
    lib_names   = [item['name'] for item in libs]

    out_file = ("results_ropchains_jop.tsv" if JOP
                else "results_ropchains_ropblock.tsv" if ROPBLOCK
                else "results_ropchains_rop.tsv")

    df = pd.DataFrame(
        [[item['size_mb']] + [False] * len(chain_names) for item in libs],
        index=lib_names,
        columns=['size_mb'] + chain_names,
    )
    df.index.name   = "library"
    df.columns.name = "ropchain"
    df.to_csv(out_file, sep="\t")

    try:
        run_tasks(libs, ropchain_files, _ropchains_lib_worker, df, out_file, is_ropchain=True)
    except KeyboardInterrupt:
        print("\nInterrupted — saving partial results …", file=sys.stderr)
        df.to_csv(out_file, sep="\t")

    hits = int(df[chain_names].values.sum())
    total_combinations = len(libs) * len(ropchain_files)
    print(f"\nResults ({hits}/{total_combinations} combinations found a valid ropchain):")
    print(df.to_string())
    print(f"\nSaved to {out_file!r}")
    print(f"Completed in {time.time() - t1:.2f} seconds")


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
        help='directory of ropchain files (.rop or .txt). Produces a boolean matrix.',
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
    ropchains  = args.ropchains  or config.get('ropchains')
    presence   = args.presence   if args.presence   is not None \
        else (str(config.get('mode', '')).lower() == 'presence')

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

    if ropchains:
        main_ropchains(libs_spec, ropchains)
    elif presence:
        main_presence(libs_spec)
    else:
        main(libs_spec)

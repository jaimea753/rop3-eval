#!/usr/bin/env python3
"""compare-tools.py — benchmark rop3 vs ropper vs angrop on ROP-chain construction.

Companion to run-experiments.py. Where run-experiments.py measures rop3 alone,
this driver runs the SAME semantic goals (execve / mprotect / turing) through
three tools and records, per (tool, binary, chain), whether each tool can build
the chain and how long it takes.

The three tools do not share a chain language, so each is driven through its own
native interface, described by the per-tool files under ropchains/:

    ropchains/rop3/<goal>_<arch>.txt   rop3 ROPLang DSL (run via the rop3 API)
    ropchains/ropper/<goal>_<arch>.spec  the verbatim `ropper --chain` argument
    ropchains/angrop/<goal>_<arch>.py    a build(project, rop) angrop snippet

The rop3 set is the reference universe of (goal, arch) pairs. A pair a tool has
no file for is reported status=unsupported (ropper: x86/x86_64 chains only;
angrop: no riscv, no turing) so the comparison matrix stays complete instead of
silently sparse.

Output: results/<config-stem>/results_compare.tsv, long format
    tool  library  arch  chain  found  seconds  extract_seconds  status
plus run-meta.yaml recording all three tool versions and the machine block.

Measurement note: gadget loading and chain construction are timed and bounded
separately. `extract_seconds` is the tool's gadget-loading cost (rop3 gadgets(),
angrop find_gadgets(), both self-reported cold-start; empty for ropper, whose
--chain CLI is a single atomic call that cannot be split). `seconds` is the
chain-construction/search cost only for rop3/angrop, and the full load+build
wall time for ropper. Loading is bounded by `load_timeout` and construction by
`chain_timeout`; a load-phase timeout is recorded status=load-timeout, a
construction-phase timeout status=timeout. Every tool reloads the binary per
chain, so the numbers are cold-start and comparable.

Usage:
    python compare-tools.py --config experiments/compare_ropchains.yaml
Parts of the surrounding harness were LLM generated (see run-experiments.py).
"""
import argparse
import datetime
import glob
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time

import pandas as pd
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "utils"))
try:
    import machine_specs
    import benchcache
except ImportError as exc:                          # pragma: no cover
    machine_specs = benchcache = None
    print(f"[WARN] utils helpers unavailable ({exc}): no cache / provenance",
          file=sys.stderr)

try:
    import resource
    HAS_RESOURCE = True
except ImportError:                                 # pragma: no cover
    HAS_RESOURCE = False


# --- Reuse the field-tested helpers from run-experiments.py ------------------
# It is hyphenated (not importable by name); loading it only runs module-level
# imports (argparse is guarded by __main__), so this is side-effect free.
def _load_runexp():
    path = os.path.join(HERE, "run-experiments.py")
    spec = importlib.util.spec_from_file_location("runexp", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


runexp = _load_runexp()
get_libs = runexp.get_libs                 # folder/file/glob/list -> lib items
_binary_arch_key = runexp._binary_arch_key  # ELF/PE header -> x86/x86_64/aarch64/riscv64
_CHAIN_ARCH_TOKENS = runexp._CHAIN_ARCH_TOKENS

TOOL_EXT = {"rop3": ".txt", "ropper": ".spec", "angrop": ".py"}


class _Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise _Timeout()


def _arm(timeout):
    """Arm a one-shot SIGALRM `timeout` seconds out (no-op if falsy). Returns
    whether an alarm was armed, so the caller knows to disarm in finally."""
    if not timeout:
        return False
    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    return True


def _disarm():
    signal.setitimer(signal.ITIMER_REAL, 0)


def _apply_memory_limit():
    """Cap this process's address space so a huge binary raises a catchable
    MemoryError instead of being OOM-killed (mirrors run-experiments.py)."""
    if not HAS_RESOURCE:
        return
    hard = 16 * 1024 * 1024 * 1024
    try:
        phys = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        cap = max(1024 ** 3, min(hard, int(phys * 0.75)))
    except (ValueError, OSError, AttributeError):
        cap = hard
    try:
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
    except Exception as e:                          # pragma: no cover
        print(f"  [WARN] could not set memory limit: {e}", file=sys.stderr)


# --- Chain identity ---------------------------------------------------------
def _split_goal_arch(stem):
    """('mprotect_amd64') -> ('mprotect', 'x86_64'); arch None if no token."""
    toks = stem.replace("-", "_").split("_")
    if toks and toks[-1] in _CHAIN_ARCH_TOKENS:
        return "_".join(toks[:-1]), _CHAIN_ARCH_TOKENS[toks[-1]]
    return stem, None


def reference_chains(ropchains_root):
    """The (goal, arch) universe, taken from ropchains/rop3/*.{txt,rop}."""
    rop3_dir = os.path.join(ropchains_root, "rop3")
    files = sorted(glob.glob(os.path.join(rop3_dir, "*.txt")) +
                   glob.glob(os.path.join(rop3_dir, "*.rop")))
    chains = []
    for f in files:
        stem = os.path.splitext(os.path.basename(f))[0]
        goal, arch = _split_goal_arch(stem)
        chains.append({"chain": stem, "goal": goal, "arch": arch, "rop3_file": f})
    return chains


def tool_file(ropchains_root, tool, chain_id):
    """Path to `tool`'s description of chain_id, or None if it has none."""
    p = os.path.join(ropchains_root, tool, chain_id + TOOL_EXT[tool])
    return p if os.path.isfile(p) else None


def _resolve_depth(depth_map, arch_key, fallback=10):
    if not depth_map:
        return fallback
    if arch_key in depth_map:
        return depth_map[arch_key]
    return depth_map.get("default", fallback)


# --- Per-tool runners -------------------------------------------------------
_rop3_mods = {}


def _ensure_rop3(rop3_folder):
    if _rop3_mods:
        return True
    try:
        runexp.prepare_env(rop3_folder)   # validates rop3.py + appends sys.path
        import rop3.api as api
        import rop3.ropchain as rc
        _rop3_mods["api"] = api
        _rop3_mods["rc"] = rc
        return True
    except SystemExit:
        # prepare_env exits if the folder is not a rop3 checkout.
        print("  [WARN] rop3 folder invalid or submodule not checked out; "
              "rop3 rows will be 'error'", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"  [WARN] cannot load rop3 ({exc}); rop3 rows will be 'error'",
              file=sys.stderr)
        return False


def run_rop3(lib_item, chain, depth_map, rop3_flags, load_timeout, chain_timeout):
    """Load gadgets under `load_timeout`, then search under `chain_timeout`, timing
    each phase separately. Returns (found, extract_seconds, seconds, status,
    chain_text): a load-phase timeout is status=load-timeout (extract measured,
    seconds None); a construction-phase timeout is status=timeout."""
    if not _rop3_mods:
        return False, None, None, "error", ""
    api, rc = _rop3_mods["api"], _rop3_mods["rc"]
    from rop3.arch import arch_singleton
    arch_singleton.reset()
    depth = _resolve_depth(depth_map, chain["arch"])

    # --- Load phase: Rop3() + gadgets() ------------------------------------
    t0 = time.perf_counter()
    armed = False
    try:
        armed = _arm(load_timeout)
        rop = api.Rop3(lib_item["files"], depth=depth, rop=True, jop=False,
                       ropblock=False, **rop3_flags)
        rop.gadgets()
    except _Timeout:
        return False, round(time.perf_counter() - t0, 4), None, "load-timeout", ""
    except MemoryError:
        print(f"  [WARN] rop3 × {chain['chain']} × {lib_item['name']}: OOM (load)",
              file=sys.stderr)
        return False, round(time.perf_counter() - t0, 4), None, "error", ""
    except Exception as exc:
        print(f"  [WARN] rop3 × {chain['chain']} × {lib_item['name']}: "
              f"{type(exc).__name__}: {exc} (load)", file=sys.stderr)
        return False, round(time.perf_counter() - t0, 4), None, "error", ""
    finally:
        if armed:
            _disarm()
    extract_seconds = round(time.perf_counter() - t0, 4)

    # --- Build phase: ropchain() search ------------------------------------
    t1 = time.perf_counter()
    armed = False
    chain_text = ""
    try:
        armed = _arm(chain_timeout)
        # The yielded solution is the resolved chain (a list[Gadget]); render it
        # via Gadget.__str__ so the actual chain is recorded, not just its cost.
        sol = next(rop.ropchain(chain["rop3_file"]))
        chain_text = "\n".join(str(g) for g in sol)
        found, status = True, "found"
    except (rc.RopChainNotFound, StopIteration):
        found, status = False, "not-found"
    except _Timeout:
        found, status = False, "timeout"
    except MemoryError:
        print(f"  [WARN] rop3 × {chain['chain']} × {lib_item['name']}: OOM (build)",
              file=sys.stderr)
        found, status = False, "error"
    except Exception as exc:
        print(f"  [WARN] rop3 × {chain['chain']} × {lib_item['name']}: "
              f"{type(exc).__name__}: {exc} (build)", file=sys.stderr)
        found, status = False, "error"
    finally:
        if armed:
            _disarm()
    return found, extract_seconds, round(time.perf_counter() - t1, 4), status, chain_text


def run_ropper(ropper_bin, lib_item, spec_file, load_timeout, chain_timeout):
    """ropper's --chain CLI loads gadgets and builds the chain in one atomic
    invocation, so load and build cannot be timed or bounded separately: its
    extract_seconds is always None and `seconds` is the full load+build wall
    time, bounded by the *sum* of the two budgets. Returns
    (found, None, seconds, status, chain_text)."""
    with open(spec_file) as f:
        chain_arg = f.read().strip()
    cmd = [ropper_bin, "--file", lib_item["files"][0], "--chain", chain_arg,
           "--nocolor"]
    budget = (load_timeout or 0) + (chain_timeout or 0) or None
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=budget)
    except subprocess.TimeoutExpired:
        return False, None, round(time.perf_counter() - t0, 4), "timeout", ""
    except FileNotFoundError:
        return False, None, None, "error", ""     # ropper not installed
    secs = round(time.perf_counter() - t0, 4)
    # ropper exits 0 even when it cannot build a chain (e.g. execve on x86_64,
    # which this version reports as a "future feature"), so trust its explicit
    # success line rather than the return code: on success it prints the chain
    # followed by "[INFO] rop chain generated!".
    stdout = p.stdout or ""
    blob = (stdout + "\n" + (p.stderr or "")).lower()
    ok = "rop chain generated" in blob
    if not ok:
        return False, None, secs, "not-found", ""
    # On success ropper printed the assembled chain (a python payload snippet)
    # ahead of the sentinel; keep that as the recorded chain text.
    chain_text = _ropper_chain_text(stdout)
    return True, None, secs, "found", chain_text


def _ropper_chain_text(stdout):
    """Extract ropper's printed chain from its --chain stdout: the lines up to
    (and including) the "rop chain generated" sentinel, trimmed."""
    lines = stdout.splitlines()
    for i, line in enumerate(lines):
        if "rop chain generated" in line.lower():
            return "\n".join(lines[:i + 1]).strip()
    return stdout.strip()


def _last_json_line(text):
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return None


def run_angrop(venv_python, lib_item, spec_file, load_timeout, chain_timeout):
    cmd = [venv_python, os.path.join(HERE, "utils", "angrop_worker.py"),
           "--binary", lib_item["files"][0], "--spec", spec_file,
           "--load-timeout", str(int(load_timeout or 0)),
           "--build-timeout", str(int(chain_timeout or 0))]
    # Outer guard well above the worker's own watchdogs so a hung interpreter is
    # still reaped; the worker reports 'timeout'/'load-timeout' itself normally.
    budget = (load_timeout or 0) + (chain_timeout or 0)
    outer = (budget + 120) if budget else None
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=outer)
    except subprocess.TimeoutExpired:
        return False, None, round(time.perf_counter() - t0, 4), "timeout", ""
    except FileNotFoundError:
        return False, None, None, "error", ""     # venv python missing
    res = _last_json_line(p.stdout)
    if res is None:
        if p.stderr:
            print(f"  [WARN] angrop worker gave no result: "
                  f"{p.stderr.strip().splitlines()[-1] if p.stderr.strip() else '?'}",
                  file=sys.stderr)
        return False, None, None, "error", ""
    return (bool(res.get("found")), res.get("extract_seconds"),
            res.get("seconds"), res.get("status", "error"),
            res.get("chain", "") or "")


# --- Tool versions (provenance + cache key) ---------------------------------
def tool_versions(cfg, rop3_folder):
    """Version/identity of each enabled tool, for provenance and the cache key."""
    tools = cfg["tools"]
    versions = {}
    if "rop3" in tools:
        versions["rop3"] = benchcache.rop3_commit(rop3_folder) if benchcache else None
    if "ropper" in tools:
        versions["ropper"] = _probe(f"{cfg['ropper_bin']} --version")
    if "angrop" in tools:
        versions["angr_angrop"] = _probe(
            f"{cfg['venv_python']} -c "
            "\"import angrop,angr;print('angrop',angrop.__version__,"
            "'angr',angr.__version__)\"")
    return versions


def _probe(shell_cmd):
    try:
        p = subprocess.run(shell_cmd, shell=True, capture_output=True,
                           text=True, timeout=60)
        out = (p.stdout or p.stderr or "").strip().splitlines()
        return out[0] if out else None
    except Exception:
        return None


# --- Collector --------------------------------------------------------------
def _tsv_escape(s):
    """Flatten a multi-line chain into one TSV cell: escape backslash then the
    structural characters (tab/CR/LF) so every result stays on a single line.
    utils/build_site.py reverses this before display."""
    if not s:
        return ""
    return (s.replace("\\", "\\\\").replace("\t", "\\t")
             .replace("\r", "\\r").replace("\n", "\\n"))


class RowCollector:
    COLUMNS = ["tool", "library", "arch", "chain", "found", "seconds",
               "extract_seconds", "status", "chain_text"]

    def __init__(self, out_file):
        self.out_file = out_file
        self.rows = []

    def add_payload(self, lib_name, payload):
        arch = payload.get("arch", "unknown")
        for r in payload.get("rows", []):
            self.rows.append({
                "tool": r["tool"], "library": lib_name, "arch": arch,
                "chain": r["chain"], "found": r["found"],
                "seconds": r["seconds"], "extract_seconds": r.get("extract_seconds"),
                "status": r["status"],
                "chain_text": _tsv_escape(r.get("chain_text", "")),
            })
            mark = "✓" if r["found"] else "✗"
            secs = "n/a" if r["seconds"] is None else f"{r['seconds']:.2f}s"
            ext = r.get("extract_seconds")
            load = "" if ext is None else f", load {ext:.2f}s"
            print(f"    {mark}  {r['tool']:<7} {lib_name} × {r['chain']}: "
                  f"{r['status']} ({secs}{load})", flush=True)

    def save(self):
        df = pd.DataFrame(self.rows, columns=self.COLUMNS)
        if not df.empty:
            df = df.sort_values(["library", "chain", "tool"]).reset_index(drop=True)
        df.to_csv(self.out_file, sep="\t", index=False)

    def summary(self):
        found = sum(1 for r in self.rows if r["found"])
        return found, len(self.rows)


# --- One binary across all tools/chains -------------------------------------
def process_library(lib_item, chains, tools, cfg):
    """Return the cache payload {'arch':..., 'rows':[...]} for one binary."""
    arch_key = _binary_arch_key(lib_item)
    depth_map = cfg["depth"]
    rop3_flags = cfg["rop3_flags"]
    load_timeout = cfg["load_timeout"]
    chain_timeout = cfg["chain_timeout"]
    rows = []
    for chain in chains:
        # Only run a chain against binaries of its architecture (arch-agnostic
        # chains — arch None — run against every binary).
        if chain["arch"] is not None and arch_key is not None \
                and chain["arch"] != arch_key:
            continue
        for tool in tools:
            chain_text = ""
            extract_secs = None
            if tool == "rop3":
                found, extract_secs, secs, status, chain_text = run_rop3(
                    lib_item, chain, depth_map, rop3_flags,
                    load_timeout, chain_timeout)
            else:
                f = tool_file(cfg["ropchains"], tool, chain["chain"])
                if f is None:
                    found, secs, status = False, None, "unsupported"
                elif tool == "ropper":
                    found, extract_secs, secs, status, chain_text = run_ropper(
                        cfg["ropper_bin"], lib_item, f,
                        load_timeout, chain_timeout)
                else:  # angrop
                    found, extract_secs, secs, status, chain_text = run_angrop(
                        cfg["venv_python"], lib_item, f,
                        load_timeout, chain_timeout)
            rows.append({"tool": tool, "chain": chain["chain"],
                         "found": found, "seconds": secs,
                         "extract_seconds": extract_secs, "status": status,
                         "chain_text": chain_text})
    return {"arch": arch_key or "unknown", "rows": rows}


# --- Provenance -------------------------------------------------------------
def write_run_meta(out_dir, cfg, versions, elapsed, n_libs, cache):
    meta = {
        "generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "results": "results_compare.tsv",
        "mode": "compare",
        "experiment": cfg.get("name"),
        "config": os.path.basename(cfg["_config_path"]),
        "config_hash": (benchcache.config_hash(cfg, "compare")
                        if benchcache else None),
        "tools": cfg["tools"],
        "tool_versions": versions,
        "elapsed_seconds": round(elapsed, 2),
        "libraries": n_libs,
        "reused_from_cache": cache.hits if cache is not None else 0,
        "sequential": True,
        "machine": machine_specs.load() if machine_specs else None,
    }
    path = os.path.join(out_dir, "run-meta.yaml")
    try:
        with open(path, "w") as f:
            if machine_specs is not None:
                machine_specs.dump_yaml(meta, f)
            else:
                yaml.safe_dump(meta, f, sort_keys=False, allow_unicode=True)
        print(f"Run metadata saved to {path!r}")
    except Exception as exc:                         # pragma: no cover
        print(f"[WARN] could not write {path}: {exc}", file=sys.stderr)


# --- Cache ------------------------------------------------------------------
def make_cache(cfg, versions, chains, enabled, refresh):
    """A benchcache.Cache keyed on machine + all three tool versions + config +
    chain-file contents, or None. The composite engine id means a ropper/angrop
    upgrade (not just a rop3 commit) correctly invalidates the reuse."""
    if not enabled or benchcache is None:
        return None
    machine = ((machine_specs.load() or {}).get("id")
               if machine_specs else None) or \
        (machine_specs.machine_id() if machine_specs else None)
    if not machine:
        print("[WARN] machine id unknown: running without cache", file=sys.stderr)
        return None
    engine = (f"rop3={versions.get('rop3')};ropper={versions.get('ropper')};"
              f"angrop={versions.get('angr_angrop')};tools={'+'.join(cfg['tools'])}")
    # Fingerprint every per-tool chain file, not just rop3's, so editing a spec
    # invalidates the affected library results.
    all_files = [c["rop3_file"] for c in chains]
    for c in chains:
        for tool in ("ropper", "angrop"):
            f = tool_file(cfg["ropchains"], tool, c["chain"])
            if f:
                all_files.append(f)
    cache = benchcache.Cache(
        benchcache.DEFAULT_CACHE_DIR,
        machine=str(machine),
        commit=engine,
        cfg_hash=benchcache.config_hash(cfg, "compare"),
        items=benchcache.fingerprint_items(all_files),
        mode="compare",
        read=not refresh,
        write=True,
    )
    print(f"Cache {cache.dir} — machine {machine} · {engine}")
    return cache


# --- Config -----------------------------------------------------------------
DEFAULTS = {
    # angr/angrop come from requirements.txt (pip, see shell.nix), so angrop is
    # a first-class tool. Drop it from a config's tools: to skip it.
    "tools": ["rop3", "ropper", "angrop"],
    # Gadget loading and chain construction are bounded separately: loading gets
    # the longer budget so a slow full-libc load can't starve the search.
    "load_timeout": 1800,
    "chain_timeout": 1800,
    "depth": {"default": None, "x86": 10, "x86_64": 10,
              "aarch64": 50, "riscv64": 50},
    "rop3_flags": {"ret_imm": False, "reg_aliases": False,
                   "keep_contradictory": False, "framed": True, "all": False},
    # Interpreter that runs utils/angrop_worker.py. Defaults to the one running
    # this driver, which is the .venv python whenever the harness itself is run
    # from it — override in the config to point angrop at another environment.
    "venv_python": sys.executable,
    "ropper_bin": "ropper",
    "rop3": os.path.join(HERE, "rop3"),
}


def load_config(path):
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    if not isinstance(cfg, dict):
        print(f"ERROR: config {path!r} must be a YAML mapping.", file=sys.stderr)
        sys.exit(1)
    merged = dict(DEFAULTS)
    merged.update(cfg)
    merged["_config_path"] = path
    return merged


def _abspath(cfg, key):
    v = cfg.get(key)
    if v and not os.path.isabs(v):
        cfg[key] = os.path.normpath(os.path.join(HERE, v))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Compare rop3, ropper and angrop on "
                                             "ROP-chain construction.")
    ap.add_argument("--config", required=True, metavar="FILE",
                    help="YAML config (see experiments/compare_ropchains.yaml).")
    ap.add_argument("--tools", metavar="LIST",
                    help="comma-separated subset override (rop3,ropper,angrop).")
    ap.add_argument("--load-timeout", type=float, default=None, metavar="SEC",
                    help="gadget-loading timeout (rop3/angrop; 0 = unlimited). "
                         "Config key: 'load_timeout'.")
    ap.add_argument("--chain-timeout", type=float, default=None, metavar="SEC",
                    help="chain-construction timeout (0 = unlimited). "
                         "Config key: 'chain_timeout'.")
    ap.add_argument("--limit", type=int, default=None, metavar="N",
                    help="only process the first N binaries (quick smoke test).")
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--refresh-cache", action="store_true")
    ap.add_argument("--out-dir", default=None, metavar="DIR",
                    help="results directory (default results/<config-stem>/).")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.config):
        print(f"ERROR: config not found: {args.config!r}", file=sys.stderr)
        sys.exit(1)
    cfg = load_config(args.config)
    print(f"Using config {args.config!r}")

    # CLI overrides.
    if args.tools:
        cfg["tools"] = [t.strip() for t in args.tools.split(",") if t.strip()]
    if args.load_timeout is not None:
        cfg["load_timeout"] = args.load_timeout or None
    elif cfg.get("load_timeout") in (0, None):
        cfg["load_timeout"] = None
    if args.chain_timeout is not None:
        cfg["chain_timeout"] = args.chain_timeout or None
    elif cfg.get("chain_timeout") in (0, None):
        cfg["chain_timeout"] = None

    # Resolve relative paths (config lives at the repo root, invoked from anywhere).
    for key in ("libraries", "ropchains", "rop3"):
        _abspath(cfg, key)
    # venv_python may be a bare command ("python3") or a path ("./.venv/bin/python");
    # only resolve the latter, never turn a command into REPO_ROOT/<command>.
    vp = cfg.get("venv_python")
    if vp and os.sep in vp and not os.path.isabs(vp):
        cfg["venv_python"] = os.path.normpath(os.path.join(HERE, vp))

    if not cfg.get("libraries"):
        print("ERROR: config missing 'libraries'.", file=sys.stderr)
        sys.exit(1)
    if not cfg.get("ropchains") or not os.path.isdir(cfg["ropchains"]):
        print(f"ERROR: ropchains dir not found: {cfg.get('ropchains')!r}",
              file=sys.stderr)
        sys.exit(1)

    _apply_memory_limit()

    libs = get_libs(cfg["libraries"])
    if args.limit:
        libs = libs[:args.limit]
    if not libs:
        print("ERROR: no libraries found.", file=sys.stderr)
        sys.exit(1)
    chains = reference_chains(cfg["ropchains"])
    if not chains:
        print(f"ERROR: no rop3 reference chains under {cfg['ropchains']}/rop3/.",
              file=sys.stderr)
        sys.exit(1)

    tools = cfg["tools"]
    if "rop3" in tools:
        _ensure_rop3(cfg["rop3"])

    versions = tool_versions(cfg, cfg["rop3"])
    print("Tool versions:")
    for k, v in versions.items():
        print(f"  {k}: {v}")

    out_dir = args.out_dir or os.path.join(
        HERE, "results",
        os.path.splitext(os.path.basename(args.config))[0])
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "results_compare.tsv")
    collector = RowCollector(out_file)
    collector.save()   # header/checkpoint exists immediately

    cache = make_cache(cfg, versions, chains,
                       enabled=(not args.no_cache) and cfg.get("cache", True),
                       refresh=args.refresh_cache)

    t0 = time.time()
    total = len(libs)
    print(f"Comparing {len(tools)} tool(s) over {total} binar"
          f"{'y' if total == 1 else 'ies'} × {len(chains)} chain(s) [sequential]")
    try:
        for i, lib in enumerate(libs, 1):
            payload = cache.get(lib["name"]) if cache is not None else None
            if payload is not None:
                collector.add_payload(lib["name"], payload)
                print(f"  [cache] {lib['name']} [{i}/{total}]", flush=True)
            else:
                payload = process_library(lib, chains, tools, cfg)
                # A row with status 'error' is environmental (OOM/engine crash/
                # missing tool), not a stable answer, so don't cache that binary.
                cacheable = not any(r["status"] == "error"
                                    for r in payload["rows"])
                if cache is not None and cacheable:
                    cache.put(lib["name"], payload)
                collector.add_payload(lib["name"], payload)
                print(f"  [{i}/{total} binaries] → checkpoint", flush=True)
            collector.save()
    except KeyboardInterrupt:
        print("\nInterrupted — saving partial results …", file=sys.stderr)
        collector.save()

    found, matched = collector.summary()
    print(f"\n{found}/{matched} (tool, binary, chain) cells realizable.")
    print(f"Saved to {out_file!r}")
    print(f"Completed in {time.time() - t0:.2f} seconds")
    write_run_meta(out_dir, cfg, versions, time.time() - t0, len(libs), cache)


if __name__ == "__main__":
    main()

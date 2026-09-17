#!/usr/bin/env python3
"""
Run every experiment config in experiments/ through run-experiments.py, each
into its own results/<config-stem>/ directory.

run-experiments.py derives its output TSV filename from the basename of the
`libraries` path in the config, not from the config's own filename, and always
writes into the current working directory (no --output-dir). Two configs
pointed at library folders with the same basename would collide on the same
output filename if run from a shared directory, so each config is instead run
with its own results/<stem>/ as the working directory.

    python experiments/run_all.py            # run every experiments/*.yaml
    python experiments/run_all.py win_rop     # run just experiments/win_rop.yaml
    python experiments/run_all.py win_rop libc_tfg_rop   # run a subset

run-experiments.py resolves path-valued config keys (`libraries`, `ropchains`,
`rop3`) against the process's current working directory, not against the
config file's own location (see run-experiments.py's use of `config.get(...)`
feeding straight into os.path.isdir/isfile/glob.glob). Existing configs write
those paths relative to the repo root (e.g. `./binaries/windows`), on the
assumption that run-experiments.py is invoked from there. Since we deliberately
run each config with cwd set to its own results/<name>/ directory (to isolate
output), those relative paths would otherwise break. So before invoking, we
load the YAML, resolve any relative `libraries`/`ropchains`/`rop3` value(s)
against REPO_ROOT, and hand run-experiments.py a rewritten temp copy of the
config instead of the original.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPERIMENTS_DIR = REPO_ROOT / "experiments"
RESULTS_DIR = REPO_ROOT / "results"
DRIVER = REPO_ROOT / "run-experiments.py"

PATH_KEYS = ("libraries", "ropchains", "rop3")


def _resolve(value):
    """Resolve a single path-like value against REPO_ROOT if it's relative."""
    p = Path(value)
    return str(p if p.is_absolute() else (REPO_ROOT / p).resolve())


def _resolve_config_paths(cfg):
    """Return a copy of cfg with PATH_KEYS resolved against REPO_ROOT.

    `libraries` may be a single path or a list of paths (per template.yaml's
    documented schema); the others are always a single path when present.
    """
    resolved = dict(cfg)
    for key in PATH_KEYS:
        value = resolved.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            resolved[key] = [_resolve(v) for v in value]
        else:
            resolved[key] = _resolve(value)
    return resolved


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv

    configs = sorted(EXPERIMENTS_DIR.glob("*.yaml"))
    if not configs:
        print(f"ERROR: no *.yaml configs found in {EXPERIMENTS_DIR}", file=sys.stderr)
        return 1

    if argv:
        wanted = set(argv)
        configs = [c for c in configs if c.stem in wanted]
        missing = wanted - {c.stem for c in configs}
        if missing:
            print(f"ERROR: unknown experiment(s): {', '.join(sorted(missing))}",
                  file=sys.stderr)
            return 1

    failures = []
    for config in configs:
        name = config.stem
        out_dir = RESULTS_DIR / name
        out_dir.mkdir(parents=True, exist_ok=True)

        with open(config) as f:
            cfg = yaml.safe_load(f) or {}
        resolved_cfg = _resolve_config_paths(cfg)

        print(f"\n=== {name} ({config.relative_to(REPO_ROOT)}) ===", flush=True)
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", prefix=f"{name}-resolved-", delete=False,
        ) as tmp:
            yaml.safe_dump(resolved_cfg, tmp)
            tmp_config_path = tmp.name

        try:
            result = subprocess.run(
                [sys.executable, str(DRIVER), "--config", tmp_config_path],
                cwd=out_dir,
            )
        finally:
            Path(tmp_config_path).unlink(missing_ok=True)

        if result.returncode != 0:
            print(f"[FAIL] {name} exited with {result.returncode}", file=sys.stderr)
            failures.append(name)

    if failures:
        print(f"\n{len(failures)} experiment(s) failed: {', '.join(failures)}",
              file=sys.stderr)
        return 1

    print(f"\nAll {len(configs)} experiment(s) completed; results under {RESULTS_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

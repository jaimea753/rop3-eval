#!/usr/bin/env python3
"""
Per-library result cache for run-experiments.py.

A gadget search is deterministic: the same binary, the same rop3, the same scan
parameters give the same answer -- and in ropchains mode the same *timing*, on
the same machine. Re-running an experiment to add one binary should therefore
not re-measure the other twenty, some of which are capped at a 1800 s chain
timeout.

An entry is keyed on:

    machine id  (utils/machine_specs.machine_id, or machine.yaml's `id`)
  + rop3 commit (the submodule actually doing the searching)
  + config hash (the scan parameters that change the answer)
  + items       (the operation list, or the ropchain files and their contents)
  + library     (the name of the target)

Deliberately NOT part of the key: the *contents* of the binaries. `libraries:`
names a folder, so re-downloading or swapping a binary underneath the same
filename is invisible here. That is the one way to get a stale answer -- run
`python utils/benchcache.py --clear` whenever the corpus changes.

    python utils/benchcache.py --list        # what is cached, and for what
    python utils/benchcache.py --clear       # drop everything
    python utils/benchcache.py --prune 30    # drop entries older than 30 days
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE_DIR = REPO_ROOT / ".benchcache"

# Config keys that change *what the answer is*. `name` is cosmetic, and the
# path keys (libraries/rop3/ropchains) are excluded on purpose: experiments/
# run_all.py feeds the driver a rewritten copy of the config with those paths
# made absolute, so hashing them would tie the key to the checkout location.
# Which library is being analysed is part of the key separately, by name.
SEMANTIC_KEYS = ("mode", "jop", "ropblock", "chain_timeout", "depth",
                 "rop3_flags", "operations")
# These change measured wall-clock time but not gadget counts, so they only
# matter for the benchmark mode.
TIMING_KEYS = ("workers", "sequential")


def config_hash(config, mode):
    """Stable hash of the scan parameters that affect this mode's results."""
    keys = SEMANTIC_KEYS + (TIMING_KEYS if mode == "ropchains" else ())
    subset = {k: config.get(k) for k in keys if config.get(k) is not None}
    subset["mode"] = mode
    blob = yaml.safe_dump(subset, sort_keys=True, default_flow_style=False)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def rop3_commit(folder):
    """`git -C <folder> rev-parse HEAD` (+ '-dirty'), or None if unavailable.

    None disables the cache: without knowing which engine produced a result we
    cannot honestly reuse it.
    """
    folder = str(folder)
    if not shutil.which("git"):
        return None
    try:
        head = subprocess.run(["git", "-C", folder, "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10)
        if head.returncode != 0:
            return None
        commit = head.stdout.strip()
        status = subprocess.run(["git", "-C", folder, "status", "--porcelain"],
                                capture_output=True, text=True, timeout=30)
        if status.returncode == 0 and status.stdout.strip():
            commit += "-dirty"
        return commit
    except (OSError, subprocess.SubprocessError):
        return None


def fingerprint_items(items):
    """Hash the task list: operation names as-is, chain files by content.

    A ropchain file that is edited in place must invalidate the benchmark it
    produced, and chains living outside the rop3 submodule are not covered by
    the commit hash.
    """
    parts = []
    for item in sorted(str(i) for i in items):
        path = Path(item)
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
            parts.append(f"{path.name}:{digest}")
        else:
            parts.append(item)
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _slug(name):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:60]


class Cache:
    """Per-library store of worker payloads under one (machine, engine, config) key."""

    def __init__(self, directory, *, machine, commit, cfg_hash, items,
                 mode, read=True, write=True):
        self.dir = Path(directory)
        self.machine = machine
        self.commit = commit
        self.cfg_hash = cfg_hash
        self.items = items
        self.mode = mode
        self.read = read
        self.write = write
        self.hits = 0
        self.stored = 0

    def key(self, lib_name):
        blob = "\x1f".join([self.machine, self.commit, self.cfg_hash,
                            self.items, self.mode, lib_name])
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def path(self, lib_name):
        return self.dir / f"{_slug(lib_name)}-{self.key(lib_name)}.json"

    def get(self, lib_name):
        """The cached worker payload for this library, or None."""
        if not self.read:
            return None
        path = self.path(lib_name)
        if not path.is_file():
            return None
        try:
            entry = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            print(f"  [WARN] ignoring unreadable cache entry {path.name}: {exc}",
                  file=sys.stderr)
            return None
        payload = entry.get("payload")
        if payload is None:
            return None
        self.hits += 1
        return payload

    def put(self, lib_name, payload):
        """Store a worker payload. Silently does nothing when writing is off."""
        if not self.write:
            return
        entry = {
            "key": self.key(lib_name),
            "created": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "machine": self.machine,
            "rop3_commit": self.commit,
            "config_hash": self.cfg_hash,
            "items": self.items,
            "mode": self.mode,
            "library": lib_name,
            "payload": payload,
        }
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            tmp = self.path(lib_name).with_suffix(".json.tmp")
            tmp.write_text(json.dumps(entry, indent=1, sort_keys=False))
            os.replace(tmp, self.path(lib_name))     # never leave a half-written entry
            self.stored += 1
        except (OSError, TypeError, ValueError) as exc:
            print(f"  [WARN] could not cache {lib_name}: {exc}", file=sys.stderr)

    def describe(self):
        return (f"machine {self.machine} · rop3 {self.commit[:8] if self.commit else '?'} "
                f"· config {self.cfg_hash} · items {self.items}")


def load_entries(directory=DEFAULT_CACHE_DIR):
    """Every readable entry in the cache directory, newest first."""
    directory = Path(directory)
    entries = []
    for path in sorted(directory.glob("*.json")):
        try:
            entry = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        entry["_path"] = path
        entries.append(entry)
    entries.sort(key=lambda e: e.get("created") or "", reverse=True)
    return entries


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=str(DEFAULT_CACHE_DIR), metavar="DIR",
                    help=f"cache directory (default: {DEFAULT_CACHE_DIR})")
    ap.add_argument("--list", action="store_true", help="list cached entries")
    ap.add_argument("--clear", action="store_true", help="delete every entry")
    ap.add_argument("--prune", type=float, metavar="DAYS", default=None,
                    help="delete entries older than DAYS days")
    args = ap.parse_args(argv)

    directory = Path(args.dir)
    if not (args.list or args.clear or args.prune is not None):
        args.list = True

    if args.clear:
        if directory.is_dir():
            shutil.rmtree(directory)
            print(f"Cleared {directory}")
        else:
            print(f"Nothing to clear: {directory} does not exist")
        return 0

    entries = load_entries(directory)

    if args.prune is not None:
        cutoff = datetime.datetime.now().astimezone() - datetime.timedelta(days=args.prune)
        dropped = 0
        for entry in entries:
            created = entry.get("created")
            try:
                stamp = datetime.datetime.fromisoformat(created)
            except (TypeError, ValueError):
                continue
            if stamp < cutoff:
                entry["_path"].unlink(missing_ok=True)
                dropped += 1
        print(f"Pruned {dropped} entr{'y' if dropped == 1 else 'ies'} older than {args.prune} day(s)")
        return 0

    if not entries:
        print(f"Cache is empty ({directory})")
        return 0

    print(f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} in {directory}\n")
    print(f"{'created':<26} {'mode':<10} {'rop3':<10} {'config':<18} library")
    for entry in entries:
        commit = (entry.get("rop3_commit") or "?")[:8]
        print(f"{(entry.get('created') or '?'):<26} {(entry.get('mode') or '?'):<10} "
              f"{commit:<10} {(entry.get('config_hash') or '?'):<18} {entry.get('library')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

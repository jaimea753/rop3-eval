#!/usr/bin/env python3

###############################################################################
# This file is a script for downloading the libc libraries from many Linux    #
# and BSD systems. It was used for the work Evaluating the Execution          #
# Capabilities of Attackers on Unix Systems using Return Oriented Programming #
#                                                                             #
###############################################################################

# Dependencies: libarchive-c (reads deb/rpm/cpio/tar/xz/gz/zstd) and pyyaml.
# `command` tasks (e.g. macOS) shell out to the tools they name (brew, ipsw).

import os
import sys
import glob
import hashlib
import platform
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import yaml
import libarchive

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "libc_downloaders.yaml")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "libc-downloaders"})
    with urllib.request.urlopen(req, timeout=120) as response:
        return response.read()


def read_member(data, pattern):
    with libarchive.memory_reader(data) as archive:
        for entry in archive:
            name = entry.pathname.lstrip("./")
            if name == pattern or name.startswith(pattern):
                return b"".join(entry.get_blocks())
    return None


def extract(data, steps):
    # Walk nested archives: every step but the last names an inner archive.
    for step in steps[:-1]:
        data = read_member(data, step)
    return read_member(data, steps[-1])


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(task):
    # Compare produced file(s) against the expected sha256; warn on mismatch.
    expected = task.get("sha256")
    if not expected:
        return
    out_path = os.path.join(HERE, task["out"])
    pairs = expected.items() if isinstance(expected, dict) else [(None, expected)]
    for name, want in pairs:
        path = os.path.join(out_path, name) if name else out_path
        rel = os.path.relpath(path, HERE)
        if not os.path.exists(path):
            print(f"WARNING: {rel} missing, cannot check sha256")
        elif sha256(path) != want:
            print(f"WARNING: sha256 mismatch for {rel}")


def produce(task):
    out_path = os.path.join(HERE, task["out"])
    if os.path.exists(out_path):
        print(f"Skipping {task['out']} (already present)")
    elif "command" in task:
        # Command tasks are OS-specific (macOS Sonoma for the dyld cache).
        need = task.get("platform")
        if need and platform.system() != need:
            print(f"WARNING: skipping {task['out']}: needs {need}, "
                  f"this is {platform.system()}")
            return
        subprocess.run(task["command"], shell=True, cwd=HERE)
        print(f"Extracted {task['out']}")
    else:
        blob = extract(fetch(task["url"]), task["extract"])
        if blob is None:
            print(f"Failed {task['out']}")
            return
        with open(out_path, "wb") as out:
            out.write(blob)
        print(f"Downloaded {task['out']}")
    verify(task)


def clean():
    for path in glob.glob(os.path.join(HERE, "*.so")):
        os.remove(path)


if __name__ == "__main__":
    # Default run keeps existing outputs and only fetches what's missing;
    # `clean` removes the downloaded *.so.
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean()
        sys.exit()
    with open(CONFIG) as config:
        tasks = yaml.safe_load(config)["downloads"]
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        pool.map(produce, tasks)

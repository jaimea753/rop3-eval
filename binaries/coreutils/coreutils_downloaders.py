#!/usr/bin/env python3

###############################################################################
# This file is a script for downloading one coreutils unit from each of four  #
# implementations — GNU coreutils, the BSD base utilities (FreeBSD /rescue),  #
# busybox and the Rust uutils/coreutils — so their ROP-gadget supply can be   #
# compared. It was written for the work Evaluating the Execution Capabilities #
# of Attackers on Unix Systems using Return Oriented Programming.             #
#                                                                             #
# busybox, uutils and BSD/rescue each ship as a single static multicall       #
# binary, written out as `<impl>_<arch>_bin`. GNU coreutils has no multicall  #
# binary: Debian compiles it as ~100 individual, dynamically-linked tools, so #
# GNU is represented by a per-arch *bundle* directory (`gnu_coreutils_<arch>/`#
# holding the whole /usr/bin tool set) — the experiment driver analyses every #
# file in a subfolder together as one target, i.e. one comparable unit. Both  #
# the `*_bin` files and the bundle subfolders are picked up by the driver's   #
# folder scan.                                                                 #
###############################################################################

# Dependencies: libarchive-c (reads deb/txz/tar.gz/zstd) and pyyaml. `command`
# tasks (if any) shell out to the tools they name.

import os
import sys
import glob
import fnmatch
import shutil
import hashlib
import platform
import posixpath
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import yaml
import libarchive

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "coreutils_downloaders.yaml")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "coreutils-downloaders"})
    with urllib.request.urlopen(req, timeout=300) as response:
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


def extract_members(data, archive_steps, patterns):
    """Pull *many* members out of one archive into a {basename: bytes} map.

    `archive_steps` descends into nested inner archives first (e.g. ['data.tar']
    for a .deb); `patterns` are glob patterns matched against each entry's path
    (a `*` spans '/', so 'usr/bin/*' matches 'usr/bin/ls'). Directories and
    symlinks (which carry no data blocks) are skipped. Used for the GNU bundle,
    whose tools are shipped as individual files rather than one binary."""
    for step in archive_steps:
        data = read_member(data, step)
    found = {}
    with libarchive.memory_reader(data) as archive:
        for entry in archive:
            name = entry.pathname.lstrip("./")
            if name.endswith("/"):
                continue
            if not any(fnmatch.fnmatchcase(name, p) for p in patterns):
                continue
            blob = b"".join(entry.get_blocks())
            if blob:  # skips dirs and symlinks (no data blocks)
                found[posixpath.basename(name)] = blob
    return found


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(task):
    # Compare the produced file against the expected sha256; warn on mismatch.
    # (Optional: most entries pin reproducibility via the URL — a FreeBSD
    # RELEASE, a tagged GitHub asset, or a content-addressed snapshot file.)
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
    try:
        if os.path.exists(out_path):
            print(f"Skipping {task['out']} (already present)")
        elif "command" in task:
            # Command tasks build from source and so are host-specific: GNU
            # coreutils has no canonical prebuilt static multicall binary, so it
            # is compiled with --enable-single-binary on the host. `platform:`
            # and `arch:` gate the task to the host it can run on.
            need = task.get("platform")
            if need and platform.system() != need:
                print(f"WARNING: skipping {task['out']}: needs {need}, "
                      f"this is {platform.system()}")
                return
            need_arch = task.get("arch")
            if need_arch and platform.machine() != need_arch:
                print(f"WARNING: skipping {task['out']}: needs arch "
                      f"{need_arch}, this is {platform.machine()}")
                return
            subprocess.run(task["command"], shell=True, cwd=HERE, check=True)
            print(f"Built {task['out']}")
        elif "members" in task:
            # Bundle: pull many members (e.g. all of /usr/bin) into a directory
            # the driver analyses as one target. Used for GNU, which Debian
            # ships as individual tools rather than a single multicall binary.
            found = extract_members(fetch(task["url"]),
                                    task.get("archive", []), task["members"])
            if not found:
                print(f"Failed {task['out']} (no members matched)")
                return
            os.makedirs(out_path, exist_ok=True)
            for base, blob in sorted(found.items()):
                with open(os.path.join(out_path, base), "wb") as out:
                    out.write(blob)
            print(f"Downloaded {task['out']} ({len(found)} files)")
        else:
            blob = extract(fetch(task["url"]), task["extract"])
            if blob is None:
                print(f"Failed {task['out']}")
                return
            with open(out_path, "wb") as out:
                out.write(blob)
            print(f"Downloaded {task['out']}")
        verify(task)
    except Exception as exc:
        print(f"ERROR {task['out']}: {exc}")


def clean():
    for path in glob.glob(os.path.join(HERE, "*_bin")):
        os.remove(path)
    for path in glob.glob(os.path.join(HERE, "gnu_coreutils_*")):
        if os.path.isdir(path):
            shutil.rmtree(path)


if __name__ == "__main__":
    # Default run keeps existing outputs and only fetches what's missing;
    # `clean` removes the downloaded *_bin binaries and gnu_coreutils_* bundles.
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean()
        sys.exit()
    with open(CONFIG) as config:
        tasks = yaml.safe_load(config)["downloads"]
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        list(pool.map(produce, tasks))

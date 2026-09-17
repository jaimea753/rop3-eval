#!/usr/bin/env python3

###############################################################################
# Downloads the KnownDLLs system libraries (ntdll, kernel32, ...) for x86,   #
# amd64 and aarch64 Windows builds, resolved through winbindex               #
# (https://winbindex.m417z.com) and served from Microsoft's public symbol   #
# server. Used for the work Evaluating the Execution Capabilities of        #
# Attackers on Unix Systems using Return Oriented Programming               #
###############################################################################

# Dependencies: pyyaml (stdlib covers gzip/hashlib/urllib for everything
# else). No third-party HTTP client or winbindex client library needed:
# winbindex publishes its whole index as static, gzip-compressed JSON files.

import os
import sys
import gzip
import glob
import json
import hashlib
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "winbindex_downloaders.yaml")

INDEX_URL = ("https://raw.githubusercontent.com/m417z/winbindex/gh-pages/"
             "data/by_filename_compressed/{name}.json.gz")
SYMBOL_SERVER_URL = "https://msdl.microsoft.com/download/symbols/{name}/{timestamp:08X}{size:x}/{name}"

# PE COFF machineType values, used to sanity-check that a pinned sha256
# actually corresponds to the architecture it's filed under.
MACHINE_TYPES = {"x86": 0x14C, "amd64": 0x8664, "aarch64": 0xAA64}

_index_cache = {}


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "winbindex-downloaders"})
    with urllib.request.urlopen(req, timeout=120) as response:
        return response.read()


def fetch_index(name):
    # Cached per filename: several architectures of the same DLL share one
    # index file, and it can be a few MB.
    if name not in _index_cache:
        _index_cache[name] = json.loads(gzip.decompress(fetch(INDEX_URL.format(name=name))))
    return _index_cache[name]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def resolve_url(name, arch, pin):
    # Winbindex only indexes PE metadata, keyed by the file's own sha256;
    # the pinned hash tells us exactly which entry (build) to use. From
    # there we read the PE timestamp/virtualSize needed to build the
    # Microsoft symbol-server URL that actually serves the bytes.
    index = fetch_index(name)
    entry = index.get(pin["sha256"])
    if entry is None:
        raise ValueError(f"sha256 {pin['sha256']} not found in winbindex index for {name}")
    info = entry["fileInfo"]
    want_machine = MACHINE_TYPES[arch]
    if info["machineType"] != want_machine:
        raise ValueError(
            f"machineType {info['machineType']} for pinned sha256 doesn't match "
            f"expected {arch} ({want_machine})"
        )
    if "virtualSize" not in info:
        raise ValueError("winbindex entry has no virtualSize (delta-only, unresolved on their end)")
    return SYMBOL_SERVER_URL.format(name=name, timestamp=info["timestamp"], size=info["virtualSize"])


def produce(task):
    out_path = os.path.join(HERE, task["out"])
    if os.path.exists(out_path):
        print(f"Skipping {task['out']} (already present)")
        return
    try:
        url = resolve_url(task["name"], task["arch"], task)
        blob = fetch(url)
        digest = sha256(blob)
        if digest != task["sha256"]:
            print(f"WARNING: sha256 mismatch for {task['out']}: got {digest}")
        with open(out_path, "wb") as out:
            out.write(blob)
        print(f"Downloaded {task['out']} ({task['version']})")
    except Exception as exc:
        print(f"ERROR {task['out']}: {exc}")


def load_tasks():
    with open(CONFIG) as config:
        downloads = yaml.safe_load(config)["downloads"]
    tasks = []
    for item in downloads:
        name = item["name"]
        for arch, pin in item["architectures"].items():
            tasks.append({
                "name": name,
                "arch": arch,
                "version": pin["version"],
                "sha256": pin["sha256"],
                "out": f"{os.path.splitext(name)[0]}_{arch}.dll",
            })
    return tasks


if __name__ == "__main__":
    # Default run keeps existing outputs and only fetches what's missing.
    tasks = load_tasks()
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        list(pool.map(produce, tasks))

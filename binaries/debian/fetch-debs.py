#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# fetch-debs.py — reproducibly download library/executable binaries out of
# Debian packages, straight from snapshot.debian.org.
#
# You describe *what* you want in a small YAML file: a single snapshot value
# (so every run is byte-for-byte reproducible), a list of architectures, and a
# list of packages — each identified by its unique Debian name and the
# location(s) of the concrete binary(ies) to pull out of it. Every extracted
# binary is written out tagged by <package-name> and <architecture>.
#
# The tool resolves each package's .deb via the snapshot's per-suite Packages
# index (so the snapshot pins the exact version), downloads it, verifies its
# SHA-256, unpacks the `ar`+`tar` container in-process, and extracts the
# requested paths — following in-archive symlinks (so e.g. libc.so.6 yields the
# real libc-2.XX.so bytes).
#
# Usage:
#   python fetch-debs.py --config fetch-debs.yaml
#   python fetch-debs.py --config fetch-debs.yaml --arch amd64 --arch riscv
#   python fetch-debs.py --config fetch-debs.yaml --dry-run
#
# Only the Python stdlib + PyYAML are required. Zstd-compressed data tarballs
# (modern Debian) need either the `zstandard` module or a `zstd`/`unzstd` CLI
# on PATH; xz/gz/bz2/plain are handled by the stdlib.
# ---------------------------------------------------------------------------

from __future__ import annotations

import argparse
import bz2
import fnmatch
import gzip
import hashlib
import io
import json
import lzma
import os
import posixpath
import shutil
import subprocess
import sys
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("fetch-debs.py needs PyYAML (`pip install pyyaml`, or use shell.nix).")

SNAPSHOT_BASE = "https://snapshot.debian.org/archive"
USER_AGENT = "fetch-debs.py (rop3; snapshot.debian.org fetcher)"

# User-facing architecture token  ->  Debian binary architecture.
# The keys accept the names the task asked for (x86, amd64, aarch64, riscv) plus
# common aliases; the *tag* written to disk is whatever the user typed in YAML.
ARCH_TO_DEBIAN = {
    "x86": "i386", "i386": "i386", "x86_32": "i386", "ia32": "i386",
    "amd64": "amd64", "x86_64": "amd64", "x64": "amd64",
    "aarch64": "arm64", "arm64": "arm64",
    "riscv": "riscv64", "riscv64": "riscv64", "rv64": "riscv64",
}

# riscv64 lived in the debian-ports archive (separate pool) for years; the main
# amd64/i386/arm64 packages are in the ordinary debian archive.
PORTS_ARCHES = {"riscv64"}


class FetchError(Exception):
    """A recoverable, per-(package, arch) failure that shouldn't abort the run."""


# --------------------------------------------------------------------------- #
# HTTP                                                                         #
# --------------------------------------------------------------------------- #
def http_get(url: str, *, retries: int = 3, timeout: int = 60) -> bytes:
    """GET a URL into memory, retrying transient failures with backoff."""
    last = None
    for attempt in range(1, retries + 1):
        try:
            req = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except HTTPError as exc:
            if exc.code == 404:
                raise FetchError(f"404 Not Found: {url}") from exc
            last = exc
        except (URLError, TimeoutError, ConnectionError) as exc:
            last = exc
        if attempt < retries:
            time.sleep(1.5 * attempt)
    raise FetchError(f"GET failed after {retries} tries: {url} ({last})")


# --------------------------------------------------------------------------- #
# snapshot.debian.org Packages index                                          #
# --------------------------------------------------------------------------- #
def parse_packages_index(raw: bytes) -> dict[str, dict[str, str]]:
    """Parse a Debian `Packages` file into {package-name: {field: value}}.

    Only the fields we need are kept (single-line ones), which is enough here:
    Package, Filename, SHA256, Version, Architecture.
    """
    text = raw.decode("utf-8", "replace")
    index: dict[str, dict[str, str]] = {}
    for stanza in text.split("\n\n"):
        fields: dict[str, str] = {}
        key = None
        for line in stanza.splitlines():
            if not line:
                continue
            if line[0] in " \t":          # continuation of a multi-line field
                if key:
                    fields[key] += "\n" + line.strip()
                continue
            head, _, val = line.partition(":")
            key = head.strip()
            fields[key] = val.strip()
        name = fields.get("Package")
        if name:
            index[name] = fields
    return index


def fetch_packages_index(archive: str, snapshot: str, suite: str,
                         component: str, deb_arch: str) -> dict[str, dict[str, str]]:
    """Download + decompress the Packages index for one (suite, component, arch)."""
    base = f"{SNAPSHOT_BASE}/{archive}/{snapshot}/dists/{suite}/{component}/binary-{deb_arch}"
    for name, decomp in (("Packages.xz", lzma.decompress),
                         ("Packages.gz", gzip.decompress),
                         ("Packages", lambda b: b)):
        try:
            raw = http_get(f"{base}/{name}")
        except FetchError:
            continue
        return parse_packages_index(decomp(raw))
    raise FetchError(f"no Packages index at {base}/ (tried .xz/.gz/plain)")


# --------------------------------------------------------------------------- #
# .deb unpacking (ar container -> data tarball -> members)                     #
# --------------------------------------------------------------------------- #
def iter_ar_members(data: bytes):
    """Yield (name, bytes) for each member of a Unix `ar` archive (the .deb)."""
    if data[:8] != b"!<arch>\n":
        raise FetchError("not an ar archive (bad .deb magic)")
    off = 8
    n = len(data)
    while off + 60 <= n:
        header = data[off:off + 60]
        name = header[0:16].decode("ascii", "replace").rstrip("/ ").strip()
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            break
        off += 60
        yield name, data[off:off + size]
        off += size + (size & 1)          # members are 2-byte aligned


def decompress_data_tar(member_name: str, blob: bytes) -> bytes:
    """Decompress a data.tar.<ext> blob into raw tar bytes."""
    if member_name.endswith((".xz", ".lzma")):
        return lzma.decompress(blob)
    if member_name.endswith(".gz"):
        return gzip.decompress(blob)
    if member_name.endswith(".bz2"):
        return bz2.decompress(blob)
    if member_name.endswith(".zst"):
        return _zstd_decompress(blob)
    if member_name.endswith(".tar"):
        return blob
    raise FetchError(f"unknown data tarball compression: {member_name}")


def _zstd_decompress(blob: bytes) -> bytes:
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompress(blob, max_output_size=1 << 31)
    except ImportError:
        pass
    for cli in ("unzstd", "zstd"):
        exe = shutil.which(cli)
        if exe:
            args = [exe, "-d", "-c"] if cli == "zstd" else [exe, "-c"]
            proc = subprocess.run(args, input=blob, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            if proc.returncode == 0:
                return proc.stdout
            raise FetchError(f"{cli} failed: {proc.stderr.decode('utf-8', 'replace')[:200]}")
    raise FetchError("zstd data.tar needs the `zstandard` module or a zstd/unzstd CLI")


def deb_data_tar(deb_bytes: bytes) -> tarfile.TarFile:
    """Return an open TarFile over a .deb's data.tar.* payload."""
    for name, blob in iter_ar_members(deb_bytes):
        base = name[:-1] if name.endswith("/") else name
        if base.startswith("data.tar") or base == "data.tar":
            raw = decompress_data_tar(base, blob)
            return tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    raise FetchError("no data.tar member inside .deb")


def _norm(path: str) -> str:
    """Normalise a tar member / user pattern to a bare 'usr/bin/ls' form."""
    return path.lstrip("./").lstrip("/")


def extract_binaries(tar: tarfile.TarFile, patterns: list[str]) -> dict[str, tuple[str, bytes]]:
    """Extract members matching any glob pattern, resolving in-archive symlinks.

    Returns {matched-member-name: (source-member-name, file-bytes)}. A pattern
    with no '/' also matches on basename, so `libc.so.6` finds it in any libdir.
    """
    members = {_norm(m.name): m for m in tar.getmembers()}
    npats = [_norm(p) for p in patterns]

    def matches(norm_name: str) -> bool:
        base = posixpath.basename(norm_name)
        for pat, orig in zip(npats, patterns):
            if fnmatch.fnmatchcase(norm_name, pat):
                return True
            if "/" not in orig.strip("/") and fnmatch.fnmatchcase(base, pat):
                return True
        return False

    def resolve(name: str, _seen=None) -> tarfile.TarInfo | None:
        """Follow sym/hard links within the archive to a regular file."""
        _seen = _seen or set()
        if name in _seen:
            return None
        _seen.add(name)
        m = members.get(name)
        if m is None:
            return None
        if m.isfile():
            return m
        if m.issym() or m.islnk():
            target = m.linkname
            if m.issym() and not target.startswith("/"):
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
            return resolve(_norm(target), _seen)
        return None

    out: dict[str, tuple[str, bytes]] = {}
    for norm_name, member in members.items():
        if not (member.isfile() or member.issym() or member.islnk()):
            continue
        if not matches(norm_name):
            continue
        real = resolve(norm_name)
        if real is None:
            continue
        fobj = tar.extractfile(real)
        if fobj is None:
            continue
        out[norm_name] = (real.name, fobj.read())
    return out


# --------------------------------------------------------------------------- #
# config handling                                                             #
# --------------------------------------------------------------------------- #
def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    if not isinstance(cfg, dict):
        sys.exit(f"{path}: top level must be a mapping")
    if "snapshot" not in cfg or not str(cfg["snapshot"]).strip():
        sys.exit(f"{path}: a `snapshot:` value is required (e.g. 20240101T000000Z)")
    if not cfg.get("packages"):
        sys.exit(f"{path}: at least one entry under `packages:` is required")
    return cfg


def normalise_binaries(entry: dict) -> list[dict]:
    """A package's `binaries:` may be strings or {path:, name:} dicts."""
    result = []
    raw = entry.get("binaries") or entry.get("paths") or entry.get("location")
    if raw is None:
        raise FetchError(f"package '{entry.get('name')}' has no `binaries:` location")
    if isinstance(raw, (str, dict)):
        raw = [raw]
    for item in raw:
        if isinstance(item, str):
            result.append({"path": item, "name": None})
        elif isinstance(item, dict):
            if "path" not in item:
                raise FetchError(f"binary entry {item!r} is missing `path:`")
            result.append({"path": item["path"], "name": item.get("name")})
        else:
            raise FetchError(f"unsupported binary entry: {item!r}")
    return result


def render_name(template: str, *, pkg: str, arch: str, deb_arch: str,
                basename: str) -> str:
    stem, ext = os.path.splitext(basename)
    return template.format(name=pkg, arch=arch, deb_arch=deb_arch,
                           basename=basename, stem=stem, ext=ext)


_GLOB_CHARS = set("*?[")


def _has_glob(pattern: str) -> bool:
    return any(c in _GLOB_CHARS for c in pattern)


def _template_needs_basename(template: str) -> bool:
    """Does the output-name template depend on the extracted member's basename?"""
    return any(f"{{{key}" in template for key in ("basename", "stem", "ext"))


def predicted_outputs(bins: list[dict], *, pkg: str, arch: str, deb_arch: str,
                      name_tmpl: str, out_dir: str) -> list[str] | None:
    """Predict every output path for a (package, arch) *without* the archive.

    Returns the list of destination paths, or None when it can't be known ahead
    of extraction — i.e. a globbed `path:` whose output name still depends on the
    matched member's basename. When a path globs but its `name:` template is
    basename-independent (e.g. `libc_debian_{arch}.so`), the name is still fully
    determined, so we can decide from disk alone.
    """
    outs = []
    for b in bins:
        tmpl = b["name"] or name_tmpl
        if _has_glob(b["path"]) and _template_needs_basename(tmpl):
            return None
        basename = posixpath.basename(b["path"].rstrip("/"))
        if not basename:
            return None
        fname = render_name(tmpl, pkg=pkg, arch=arch, deb_arch=deb_arch,
                            basename=basename)
        outs.append(os.path.join(out_dir, fname))
    return outs


# --------------------------------------------------------------------------- #
# driver                                                                       #
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Download binaries from Debian packages via snapshot.debian.org.")
    ap.add_argument("--config", "-c", default="fetch-debs.yaml",
                    help="YAML config (default: fetch-debs.yaml next to CWD)")
    ap.add_argument("--output", "-o", default=None,
                    help="output directory (overrides `output:` in the config)")
    ap.add_argument("--arch", "-a", action="append", metavar="ARCH",
                    help="only fetch these arch(s); repeatable. Default: all in config")
    ap.add_argument("--package", "-p", action="append", metavar="NAME",
                    help="only fetch these package(s); repeatable")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve + print .deb URLs but download nothing")
    ap.add_argument("--keep-debs", action="store_true",
                    help="also keep the raw .deb files under <output>/.debs/")
    ap.add_argument("--force", "-f", action="store_true",
                    help="re-download and overwrite even if outputs already exist "
                         "(default: skip packages whose outputs are all present)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    snapshot = str(cfg["snapshot"]).strip()
    out_root = args.output or cfg.get("output") or "binaries"
    component = cfg.get("component", "main")
    name_tmpl = cfg.get("naming", "{name}_{arch}_{basename}")

    cfg_arches = cfg.get("architectures") or ["amd64"]
    arches = args.arch or cfg_arches
    want_pkgs = set(args.package) if args.package else None

    # Per-arch resolution knobs (archive + candidate suites), with sane defaults
    # and optional per-arch overrides in the config's `arch_options:` map.
    arch_opts = cfg.get("arch_options") or {}

    def resolve_arch(arch: str):
        deb_arch = ARCH_TO_DEBIAN.get(arch.lower(), arch.lower())
        opts = arch_opts.get(arch, arch_opts.get(deb_arch, {}))
        if deb_arch in PORTS_ARCHES:
            archive = opts.get("archive", "debian-ports")
            suites = opts.get("suites") or [cfg.get("suite", "sid"), "unreleased"]
        else:
            archive = opts.get("archive", "debian")
            suites = opts.get("suites") or [cfg.get("suite", "sid")]
        return deb_arch, archive, suites

    print(f"snapshot : {snapshot}")
    print(f"output   : {out_root}")
    print(f"arches   : {', '.join(arches)}")
    print(f"packages : {len(cfg['packages'])}\n")

    manifest = {"snapshot": snapshot, "component": component, "entries": []}
    index_cache: dict[tuple, dict] = {}
    n_ok = n_fail = 0

    # Reuse the previous manifest (if any) so cached entries can carry over their
    # version/suite/deb_url without re-fetching anything. Keyed by output path.
    prev_entries: dict[str, dict] = {}
    if not args.force:
        try:
            with open(os.path.join(out_root, "manifest.json"), encoding="utf-8") as fh:
                for e in json.load(fh).get("entries", []):
                    if isinstance(e, dict) and e.get("output"):
                        prev_entries[e["output"]] = e
        except (OSError, ValueError):
            pass

    for arch in arches:
        try:
            deb_arch, archive, suites = resolve_arch(arch)
        except Exception as exc:  # noqa: BLE001
            print(f"[{arch}] cannot resolve architecture: {exc}")
            continue

        # Load (and cache) the Packages index for each candidate suite lazily.
        def load_index(suite: str):
            key = (archive, suite, component, deb_arch)
            if key not in index_cache:
                index_cache[key] = fetch_packages_index(
                    archive, snapshot, suite, component, deb_arch)
            return index_cache[key]

        for entry in cfg["packages"]:
            pkg = entry.get("name")
            if not pkg:
                print("[skip] package entry without a `name:`")
                continue
            if want_pkgs and pkg not in want_pkgs:
                continue

            tag = f"{pkg}/{arch}"
            try:
                bins = normalise_binaries(entry)
                out_dir = os.path.join(out_root, arch)

                # Skip everything — including the Packages index fetch — when every
                # output this package would produce is already on disk (unless
                # --force or --dry-run). Metadata is carried over from the previous
                # manifest.json when present, so cached runs need no network at all.
                if not args.force and not args.dry_run:
                    predicted = predicted_outputs(
                        bins, pkg=pkg, arch=arch, deb_arch=deb_arch,
                        name_tmpl=name_tmpl, out_dir=out_dir)
                    if predicted is None:
                        # Output names can't be predicted ahead of extraction
                        # (a globbed path whose name depends on the matched
                        # member's basename). Fall back to the previous
                        # manifest: if it recorded outputs for this
                        # (package, arch) and they're all still on disk, the
                        # library is already present — skip the re-download.
                        predicted = [os.path.join(out_root, e["output"])
                                     for e in prev_entries.values()
                                     if e.get("package") == pkg
                                     and e.get("arch") == arch] or None
                    if predicted and all(os.path.exists(p) for p in predicted):
                        for p in predicted:
                            with open(p, "rb") as fh:
                                blob = fh.read()
                            sha = hashlib.sha256(blob).hexdigest()
                            rel = os.path.relpath(p, out_root)
                            print(f"[{tag}] cached: {rel}  ({len(blob):,} B)")
                            prev = prev_entries.get(rel, {})
                            manifest["entries"].append({
                                "package": pkg, "arch": arch, "debian_arch": deb_arch,
                                "version": prev.get("version", "?"),
                                "suite": prev.get("suite"),
                                "archive": prev.get("archive", archive),
                                "member": prev.get("member", posixpath.basename(p)),
                                "output": rel, "sha256": sha,
                                "deb_url": prev.get("deb_url"), "cached": True,
                            })
                        n_ok += 1
                        continue

                # Find the package stanza in the first suite that has it.
                stanza = None
                used_suite = None
                errors = []
                for suite in suites:
                    try:
                        stanza = load_index(suite).get(pkg)
                    except FetchError as exc:
                        errors.append(f"{suite}: {exc}")
                        stanza = None
                    if stanza:
                        used_suite = suite
                        break
                if not stanza:
                    detail = f" ({'; '.join(errors)})" if errors else ""
                    raise FetchError(
                        f"package '{pkg}' not found for {deb_arch} in "
                        f"{archive} [{', '.join(suites)}]{detail}")

                filename = stanza.get("Filename")
                if not filename:
                    raise FetchError(f"'{pkg}' stanza has no Filename")
                deb_url = f"{SNAPSHOT_BASE}/{archive}/{snapshot}/{filename}"
                version = stanza.get("Version", "?")

                if args.dry_run:
                    print(f"[{tag}] {version} @ {used_suite}\n         {deb_url}")
                    n_ok += 1
                    continue

                deb_bytes = http_get(deb_url)
                want_sha = stanza.get("SHA256")
                if want_sha:
                    got = hashlib.sha256(deb_bytes).hexdigest()
                    if got != want_sha:
                        raise FetchError(
                            f"SHA-256 mismatch for {pkg} (got {got[:12]}…, "
                            f"want {want_sha[:12]}…)")

                if args.keep_debs:
                    deb_dir = os.path.join(out_root, ".debs")
                    os.makedirs(deb_dir, exist_ok=True)
                    with open(os.path.join(deb_dir, os.path.basename(filename)), "wb") as fh:
                        fh.write(deb_bytes)

                tar = deb_data_tar(deb_bytes)
                extracted = extract_binaries(tar, [b["path"] for b in bins])

                # Report any requested pattern that matched nothing.
                for b in bins:
                    npat = _norm(b["path"])
                    if not any(fnmatch.fnmatchcase(k, npat)
                               or ("/" not in b["path"].strip("/")
                                   and fnmatch.fnmatchcase(posixpath.basename(k), npat))
                               for k in extracted):
                        print(f"[{tag}] WARNING: no member matched '{b['path']}'")

                # Choose an explicit output name if a single pattern was given a
                # `name:`; otherwise template each matched basename.
                explicit = {b["path"]: b["name"] for b in bins if b["name"]}
                os.makedirs(out_dir, exist_ok=True)

                for member_name, (src_name, blob) in sorted(extracted.items()):
                    basename = posixpath.basename(member_name)
                    chosen = None
                    for pat, nm in explicit.items():
                        np = _norm(pat)
                        if fnmatch.fnmatchcase(member_name, np) or (
                                "/" not in pat.strip("/")
                                and fnmatch.fnmatchcase(basename, np)):
                            chosen = nm
                            break
                    fname = render_name(
                        chosen or name_tmpl, pkg=pkg, arch=arch,
                        deb_arch=deb_arch, basename=basename)
                    dest = os.path.join(out_dir, fname)
                    with open(dest, "wb") as fh:
                        fh.write(blob)
                    sha = hashlib.sha256(blob).hexdigest()
                    rel = os.path.relpath(dest, out_root)
                    print(f"[{tag}] {member_name}  ->  {rel}  ({len(blob):,} B)")
                    manifest["entries"].append({
                        "package": pkg, "arch": arch, "debian_arch": deb_arch,
                        "version": version, "suite": used_suite, "archive": archive,
                        "member": src_name, "output": rel,
                        "sha256": sha, "deb_url": deb_url,
                    })
                n_ok += 1

            except FetchError as exc:
                print(f"[{tag}] FAILED: {exc}")
                n_fail += 1
            except Exception as exc:  # noqa: BLE001
                print(f"[{tag}] ERROR: {exc}")
                n_fail += 1

    if not args.dry_run:
        # Carry over manifest entries for outputs this run didn't touch (e.g. a
        # --package/--arch subset run, or a package that was skipped as cached),
        # as long as the file is still on disk. This keeps manifest.json a
        # complete record instead of shrinking to just what this invocation
        # processed — the unpredictable-name cache fallback relies on it.
        if not args.force:
            seen = {e["output"] for e in manifest["entries"]}
            for rel, e in prev_entries.items():
                if rel not in seen and os.path.exists(os.path.join(out_root, rel)):
                    manifest["entries"].append(e)
        os.makedirs(out_root, exist_ok=True)
        mpath = os.path.join(out_root, "manifest.json")
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
        print(f"\nmanifest : {mpath}  ({len(manifest['entries'])} binaries)")

    print(f"done: {n_ok} ok, {n_fail} failed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())

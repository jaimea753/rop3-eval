#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# fetch-brew.py — download binaries out of macOS Homebrew bottles, the same way
# fetch-debs.py pulls them out of Debian .debs: resolve -> download -> extract
# the requested members -> write a manifest.
#
# A bottle is a .tar.gz of a formula's compiled Mach-O binaries, hosted on
# ghcr.io (GitHub Packages). To pin the corpus to one macOS release, this tool
# resolves bottles straight from ghcr.io's OCI manifest index rather than the
# formulae.brew.sh `files` map: the API only ever lists the *latest* version for
# the *currently-built* platforms (it no longer carries Intel macOS bottles at
# all), whereas ghcr still retains every historical per-release bottle. For each
# formula it lists the version tags on ghcr, walks them newest-first, and takes
# the newest version that has a bottle for the requested release, in the config's
# release-preference order (e.g. `arm64_golden_gate` then `arm64_tahoe`), so an
# arch gets the latest macOS release it is built for. A `version:` pin in the
# config selects one directly instead. The bottle is pulled from ghcr.io using
# Homebrew's anonymous bearer token; its sha256 is the ghcr content digest, so
# verification is inherent. Extraction follows in-archive symlinks.
#
# It also handles `casks:` — desktop GUI apps. A cask's binary is not hosted by
# Homebrew: the API gives a vendor download (.dmg / .pkg / .zip) plus its
# sha256 and the `.app` it installs. This tool downloads that artifact, reads
# the app's main Mach-O executable (Contents/MacOS/<CFBundleExecutable>), and —
# since desktop apps are usually universal (fat) binaries — slices out a thin
# per-arch binary. .zip is handled with the stdlib; .dmg/.pkg need a `7z`/`7zz`
# (p7zip) on PATH, which shell.nix provides.
#
# Homebrew only publishes macOS bottles, so the only architectures available are
# x86_64 (Intel) and arm64 (Apple Silicon / aarch64). The `platforms:` lists set
# the release preference (newest macOS first by default, so each arch gets its
# latest build); the resolved formula version + bottle sha256 are recorded in
# manifest.json. For a fully frozen corpus, pin each formula's `version:` so the
# exact bottle is fetched instead of "newest version with a <release> bottle".
#
# Usage:
#   python fetch-brew.py --config fetch-brew.yaml
#   python fetch-brew.py --config fetch-brew.yaml --arch aarch64
#   python fetch-brew.py --config fetch-brew.yaml --dry-run
#
# Only the Python stdlib + PyYAML are required.
# ---------------------------------------------------------------------------

from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import io
import json
import os
import plistlib
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("fetch-brew.py needs PyYAML (`pip install pyyaml`, or use shell.nix).")

USER_AGENT = "fetch-brew.py (rop3; Homebrew bottle fetcher)"
# Homebrew's hard-coded anonymous token for public ghcr.io bottle pulls.
GHCR_ANON_TOKEN = "QQ=="

# User-facing architecture token -> the only two arches macOS bottles exist for.
ARCH_ALIASES = {
    "amd64": "amd64", "x86_64": "amd64", "x64": "amd64", "intel": "amd64",
    "aarch64": "aarch64", "arm64": "aarch64", "apple_silicon": "aarch64",
}


class FetchError(Exception):
    """A recoverable, per-(formula, arch) failure that shouldn't abort the run."""


# --------------------------------------------------------------------------- #
# HTTP                                                                         #
# --------------------------------------------------------------------------- #
def http_get(url: str, *, headers: dict | None = None,
             retries: int = 3, timeout: int = 120) -> bytes:
    """GET a URL into memory, retrying transient failures with backoff."""
    last = None
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    for attempt in range(1, retries + 1):
        try:
            req = Request(url, headers=hdrs)
            with urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except HTTPError as exc:
            if exc.code == 404:
                raise FetchError(f"404 Not Found: {url}") from exc
            last = exc
            # A 401 from ghcr means our token isn't accepted; let the caller retry
            # with a freshly-minted token rather than burning the backoff budget.
            if exc.code == 401:
                raise
        except (URLError, TimeoutError, ConnectionError) as exc:
            last = exc
        if attempt < retries:
            time.sleep(1.5 * attempt)
    raise FetchError(f"GET failed after {retries} tries: {url} ({last})")


def ghcr_token_for(url: str) -> str | None:
    """Mint a short-lived anonymous pull token for the repository a ghcr URL
    points at (fallback when the hard-coded QQ== token is rejected)."""
    # https://ghcr.io/v2/<repo...>/(blobs|manifests|tags)/...  ->  repo = <repo...>
    marker = "/v2/"
    i = url.find(marker)
    if i < 0:
        return None
    rest = url[i + len(marker):]
    repo = None
    for sep in ("/blobs/", "/manifests/", "/tags/"):
        j = rest.find(sep)
        if j >= 0:
            repo = rest[:j]
            break
    if not repo:
        return None
    try:
        raw = http_get(
            f"https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}:pull")
        return json.loads(raw).get("token")
    except (FetchError, ValueError):
        return None


def ghcr_get(url: str, accept: str, *, timeout: int = 120) -> bytes:
    """GET a ghcr.io URL authenticating like Homebrew does: try the hard-coded
    anonymous QQ== token, and on a 401 mint a repo-scoped token and retry."""
    headers = {"Authorization": f"Bearer {GHCR_ANON_TOKEN}", "Accept": accept}
    try:
        return http_get(url, headers=headers, timeout=timeout)
    except HTTPError as exc:
        if exc.code != 401:
            raise FetchError(f"ghcr GET failed ({exc.code}): {url}") from exc
        token = ghcr_token_for(url)
        if not token:
            raise FetchError(f"ghcr rejected the anonymous token for {url}") from exc
        headers["Authorization"] = f"Bearer {token}"
        return http_get(url, headers=headers, timeout=timeout)


def download_bottle(url: str) -> bytes:
    """Download a bottle blob from ghcr.io, authenticating like Homebrew does."""
    return ghcr_get(url, "application/vnd.oci.image.layer.v1.tar+gzip", timeout=300)


# --------------------------------------------------------------------------- #
# formulae.brew.sh resolution                                                 #
# --------------------------------------------------------------------------- #
GHCR_V2 = "https://ghcr.io/v2"
# How many versions (newest-first) to probe for a release's bottle before giving
# up — a formula's Ventura bottles sit a handful of releases behind the latest.
MAX_VERSION_SCAN = 120

_versions_cache: dict[str, list[str]] = {}       # repo -> versions, newest-first
_manifest_cache: dict[tuple[str, str], dict | None] = {}  # (repo, ver) -> index


def _ghcr_repo(formula: str) -> str:
    """Homebrew core ghcr repository for a formula (`openssl@3` -> .../openssl/3)."""
    return "homebrew/core/" + formula.replace("@", "/")


def _version_key(ver: str):
    """Sort key for Homebrew version tags (`3.4.1`, `3.6.4_1`, `3.6.3-2`): split
    on separators, compare tokens numerically where possible. A trailing
    revision/rebuild makes a version compare greater, so it ranks as newer."""
    out = []
    for tok in re.split(r"[._\-]", ver):
        if tok.isdigit():
            out.append((1, int(tok), ""))
        else:
            out.append((0, 0, tok))
    return out


def ghcr_list_versions(repo: str) -> list[str]:
    """All version tags for a ghcr repo, newest-first (following pagination)."""
    if repo in _versions_cache:
        return _versions_cache[repo]
    tags: list[str] = []
    url = f"{GHCR_V2}/{repo}/tags/list?n=100"
    token = GHCR_ANON_TOKEN
    while url:
        hdrs = {"User-Agent": USER_AGENT, "Authorization": f"Bearer {token}",
                "Accept": "application/json"}
        try:
            with urlopen(Request(url, headers=hdrs), timeout=120) as resp:
                payload = json.loads(resp.read())
                link = resp.headers.get("Link")
        except HTTPError as exc:
            if exc.code == 401 and token == GHCR_ANON_TOKEN:
                token = ghcr_token_for(url) or token
                if token != GHCR_ANON_TOKEN:
                    continue
            raise FetchError(f"tags/list failed for {repo}: {exc}") from exc
        except (URLError, TimeoutError, ConnectionError, ValueError) as exc:
            raise FetchError(f"tags/list failed for {repo}: {exc}") from exc
        tags += payload.get("tags") or []
        nxt = None
        if link:
            for part in link.split(","):
                if 'rel="next"' in part:
                    s, e = part.find("<"), part.find(">")
                    if 0 <= s < e:
                        nxt = part[s + 1:e]
        url = ("https://ghcr.io" + nxt) if nxt and nxt.startswith("/") else (nxt or "")
    versions = sorted((t for t in tags if t[:1].isdigit()),
                      key=_version_key, reverse=True)
    _versions_cache[repo] = versions
    return versions


def ghcr_manifest_index(repo: str, version: str) -> dict | None:
    """The OCI image index for one version tag (the per-release bottle list),
    or None if ghcr has no such tag. Cached per (repo, version)."""
    key = (repo, version)
    if key in _manifest_cache:
        return _manifest_cache[key]
    url = f"{GHCR_V2}/{repo}/manifests/{version}"
    try:
        idx = json.loads(ghcr_get(url, "application/vnd.oci.image.index.v1+json"))
    except (FetchError, ValueError):
        idx = None
    _manifest_cache[key] = idx
    return idx


def resolve_bottle(formula: str, tags: list[str],
                   pinned: str | None = None) -> tuple[str, str, str, str]:
    """Return (version, bottle_tag, blob_url, sha256) for the newest version of
    `formula` that has a bottle for one of `tags` (an arch's ordered release
    preference; `all` — a portable/noarch bottle — is always tried last),
    resolved from ghcr.io's OCI manifests. A `pinned` version is used directly
    instead of scanning. The bottle's sha256 is its ghcr content digest."""
    repo = _ghcr_repo(formula)
    versions = [str(pinned)] if pinned else ghcr_list_versions(repo)
    wanted = list(tags) + ["all"]
    scanned = 0
    for version in versions:
        idx = ghcr_manifest_index(repo, version)
        if not idx:
            continue
        # ref.names are "<base-version>.<os-tag>", with a trailing ".<rebuild>"
        # on a bottle rebuild (ghcr tag "3.6.3-2" -> "3.6.3.<os>.2"). Strip the
        # base version (sans any "-N" rebuild) and the rebuild suffix to recover
        # the bare os tag.
        base = version.split("-", 1)[0]
        prefix = base + "."
        refs: dict[str, str] = {}
        for man in idx.get("manifests") or []:
            ann = man.get("annotations") or {}
            name = ann.get("org.opencontainers.image.ref.name") or ""
            digest = ann.get("sh.brew.bottle.digest")
            if not (digest and name.startswith(prefix)):
                continue
            os_tag = re.sub(r"\.\d+$", "", name[len(prefix):])
            refs[os_tag] = digest
        for tag in wanted:
            digest = refs.get(tag)
            if digest:
                url = f"{GHCR_V2}/{repo}/blobs/sha256:{digest}"
                return version, tag, url, digest
        scanned += 1
        if not pinned and scanned >= MAX_VERSION_SCAN:
            break
    if pinned:
        raise FetchError(f"{formula}: version {pinned} has no bottle for {tags}")
    raise FetchError(f"{formula}: no bottle for {tags} "
                     f"(scanned {scanned} version(s) on ghcr)")


# --------------------------------------------------------------------------- #
# bottle unpacking (gzip tar -> members, resolving in-archive symlinks)        #
# --------------------------------------------------------------------------- #
def _norm(path: str) -> str:
    return path.lstrip("./").lstrip("/")


def extract_binaries(tar: tarfile.TarFile,
                     patterns: list[str]) -> dict[str, tuple[str, bytes]]:
    """Extract members matching any glob pattern, resolving in-archive symlinks.
    Returns {matched-member: (source-member, bytes)}. A pattern with no '/' also
    matches on basename. (Ported from fetch-debs.py.)"""
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

    def resolve(name: str, _seen=None):
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
                target = posixpath.normpath(
                    posixpath.join(posixpath.dirname(name), target))
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
# casks (desktop apps): resolve -> download (dmg/pkg/zip) -> slice Mach-O       #
# --------------------------------------------------------------------------- #
CASK_API_BASE = "https://formulae.brew.sh/api/cask"
# Mach-O fat-binary cpu types we slice out, mapped to our arch tokens.
MACHO_CPU = {0x01000007: "amd64", 0x0100000C: "aarch64"}
_SEVENZIP = shutil.which("7zz") or shutil.which("7z")


def _cask_arch_download(data: dict, akey: str) -> tuple[str, str]:
    """Pick (url, sha256) best matching arch `akey` ('amd64'/'aarch64'). Most
    casks have a single (often universal) top-level url; some split by arch via
    `variations` (an `arm64_*` key is Apple Silicon, a non-arm key is Intel)."""
    for key, info in (data.get("variations") or {}).items():
        if key.endswith("_linux") or not info.get("url"):
            continue
        if (akey == "aarch64") == key.startswith("arm64"):
            return info["url"], info.get("sha256", "")
    return data.get("url", ""), data.get("sha256", "")


def resolve_cask(token: str, akey: str) -> tuple[str, str, str, str | None]:
    """Return (version, url, sha256, app_bundle_name) for a cask + arch."""
    data = json.loads(http_get(f"{CASK_API_BASE}/{token}.json"))
    version = data.get("version") or "?"
    url, sha = _cask_arch_download(data, akey)
    if not url:
        raise FetchError(f"{token}: cask has no download url")
    apps: list[str] = []
    for art in data.get("artifacts") or []:
        if isinstance(art, dict) and art.get("app"):
            val = art["app"]
            apps += val if isinstance(val, list) else [val]
    app = next((a for a in apps if isinstance(a, str) and a.endswith(".app")), None)
    return version, url, sha, app


def _artifact_kind(blob: bytes, url: str) -> str:
    """zip / pkg / dmg, from magic bytes with the URL extension as a hint."""
    if blob[:2] == b"PK":
        return "zip"
    if blob[:4] == b"xar!":
        return "pkg"
    low = url.split("?")[0].lower()
    if low.endswith((".pkg", ".mpkg")):
        return "pkg"
    if low.endswith(".zip"):
        return "zip"
    return "dmg"  # UDIF disk image (koly trailer) or unknown app download


def slice_macho(blob: bytes, want: str) -> bytes | None:
    """The thin Mach-O for arch `want`: a slice of a fat binary, the binary
    itself if already a thin Mach-O of that arch, else None."""
    if len(blob) < 8:
        return None
    magic = struct.unpack(">I", blob[:4])[0]
    if magic in (0xCAFEBABE, 0xCAFEBABF):             # fat, big-endian header
        wide = magic == 0xCAFEBABF
        rec = 32 if wide else 20
        fmt = ">iiQQI" if wide else ">iiIII"
        off = 8
        for _ in range(struct.unpack(">I", blob[4:8])[0]):
            cpu, _sub, offset, size, _al = struct.unpack(fmt, blob[off:off + rec])
            off += rec
            if MACHO_CPU.get(cpu) == want:
                return blob[offset:offset + size]
        return None
    if magic in (0xCFFAEDFE, 0xCEFAEDFE):             # thin Mach-O, little-endian
        cpu = struct.unpack("<i", blob[4:8])[0]
        return blob if MACHO_CPU.get(cpu) == want else None
    return None


def _macho_from_zip(blob: bytes, exe_override: str | None,
                    app_hint: str | None) -> tuple[str, bytes]:
    z = zipfile.ZipFile(io.BytesIO(blob))
    names = z.namelist()
    apps = sorted({n.split("/", 1)[0] for n in names
                   if n.split("/", 1)[0].endswith(".app")})
    if not apps:
        raise FetchError("no .app bundle inside the zip")
    app = app_hint if app_hint in apps else apps[0]
    exe = exe_override
    if not exe:
        try:
            exe = plistlib.loads(z.read(f"{app}/Contents/Info.plist")).get(
                "CFBundleExecutable")
        except KeyError:
            exe = None
    exe = exe or app[:-4]
    try:
        return exe, z.read(f"{app}/Contents/MacOS/{exe}")
    except KeyError as exc:
        raise FetchError(f"{app}/Contents/MacOS/{exe} not in zip") from exc


def _macho_from_tree(root: str, exe_override: str | None,
                     app_hint: str | None) -> tuple[str, bytes]:
    apps = sorted(d for d, _, _ in os.walk(root) if d.endswith(".app"))
    if not apps:
        raise FetchError("no .app bundle found in the extracted image")
    app = next((a for a in apps if app_hint and os.path.basename(a) == app_hint),
               apps[0])
    exe = exe_override
    if not exe:
        try:
            with open(os.path.join(app, "Contents", "Info.plist"), "rb") as fh:
                exe = plistlib.load(fh).get("CFBundleExecutable")
        except (OSError, Exception):  # noqa: BLE001  (plist may be binary/missing)
            exe = None
    exe = exe or os.path.basename(app)[:-4]
    path = os.path.join(app, "Contents", "MacOS", exe)
    if not os.path.isfile(path):
        raise FetchError(f"executable {exe!r} not found under {os.path.basename(app)}")
    with open(path, "rb") as fh:
        return exe, fh.read()


def _run_7z(archive: str, dest: str) -> None:
    """Fully extract `archive` into `dest` with 7-Zip — every member, no include
    filter, so it works no matter how deep the app bundle is nested."""
    os.makedirs(dest, exist_ok=True)
    subprocess.run([_SEVENZIP, "x", "-y", f"-o{dest}", archive],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _tree_has_app(root: str) -> bool:
    return any(d.endswith(".app") for d, _dirs, _files in os.walk(root))


def _extract_with_7z(blob: bytes, kind: str, exe_override: str | None,
                     app_hint: str | None) -> tuple[str, bytes]:
    """Extract a macOS .app's main Mach-O from a .dmg/.pkg with 7-Zip.

    A UDIF .dmg does not expose its files at the top level: 7-Zip lists the
    filesystem as a nested volume (`2.hfs`, an Apple_HFS/APFS image), and a .pkg
    nests a cpio `Payload`. Rather than filter on `Contents/MacOS` in one pass
    (which matches nothing at the wrapper level, and depends on 7-Zip wildcard
    semantics), extract each layer in full and descend into whatever containers
    come out until an `.app` surfaces.
    """
    if not _SEVENZIP:
        raise FetchError(f"{kind} needs 7z/7zz on PATH (add p7zip/_7zz to shell.nix)")
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "artifact")
        with open(src, "wb") as fh:
            fh.write(blob)
        queue, guard = [src], 0
        while queue and guard < 8:
            guard += 1
            dest = os.path.join(td, f"x{guard}")
            _run_7z(queue.pop(0), dest)
            if _tree_has_app(dest):
                return _macho_from_tree(dest, exe_override, app_hint)
            # No app yet — this layer was a wrapper (.dmg -> volume, .pkg ->
            # Payload -> cpio). Queue the containers it produced and go deeper.
            for dirpath, _dirs, files in os.walk(dest):
                for fn in files:
                    queue.append(os.path.join(dirpath, fn))
        raise FetchError("no .app bundle found in the extracted image")


def app_main_macho(blob: bytes, url: str, exe_override: str | None,
                   app_hint: str | None) -> tuple[str, bytes]:
    """The app's main Mach-O (name, bytes), extracted per artifact type."""
    kind = _artifact_kind(blob, url)
    if kind == "zip":
        return _macho_from_zip(blob, exe_override, app_hint)
    return _extract_with_7z(blob, kind, exe_override, app_hint)


# --------------------------------------------------------------------------- #
# config handling                                                             #
# --------------------------------------------------------------------------- #
def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    if not isinstance(cfg, dict):
        sys.exit(f"{path}: top level must be a mapping")
    if not cfg.get("formulae") and not cfg.get("casks"):
        sys.exit(f"{path}: at least one entry under `formulae:` or `casks:` is required")
    return cfg


def normalise_binaries(entry: dict) -> list[dict]:
    """A formula's `binaries:` may be strings or {path:, name:} dicts."""
    result = []
    raw = entry.get("binaries") or entry.get("paths")
    if raw is None:
        raise FetchError(f"formula '{entry.get('name')}' has no `binaries:` location")
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


def render_name(template: str, *, formula: str, arch: str, basename: str) -> str:
    stem, ext = os.path.splitext(basename)
    # {name} is the formula with any @version suffix flattened for a clean filename.
    safe = formula.replace("@", "").replace("/", "_")
    return template.format(name=safe, formula=safe, arch=arch,
                           basename=basename, stem=stem, ext=ext)


# --------------------------------------------------------------------------- #
# driver                                                                       #
# --------------------------------------------------------------------------- #
DEFAULT_PLATFORMS = {
    "amd64": ["tahoe", "sequoia", "sonoma", "ventura"],
    "aarch64": ["arm64_golden_gate", "arm64_tahoe", "arm64_sequoia", "arm64_sonoma"],
}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Download binaries from macOS Homebrew bottles via ghcr.io.")
    ap.add_argument("--config", "-c", default="fetch-brew.yaml",
                    help="YAML config (default: fetch-brew.yaml)")
    ap.add_argument("--output", "-o", default=None,
                    help="output directory (overrides `output:` in the config)")
    ap.add_argument("--arch", "-a", action="append", metavar="ARCH",
                    help="only fetch these arch(s); repeatable. Default: all in config")
    ap.add_argument("--formula", "-p", action="append", metavar="NAME",
                    help="only fetch these formula(e); repeatable")
    ap.add_argument("--cask", action="append", metavar="NAME",
                    help="only fetch these cask(s); repeatable")
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve + print bottle/cask URLs but download nothing")
    ap.add_argument("--force", "-f", action="store_true",
                    help="re-download and overwrite even if outputs already exist")
    args = ap.parse_args()

    cfg = load_config(args.config)
    out_root = args.output or cfg.get("output") or "binaries"
    name_tmpl = cfg.get("naming", "{name}_brew_{arch}")
    platforms = cfg.get("platforms") or DEFAULT_PLATFORMS
    formulae = cfg.get("formulae") or []
    casks = cfg.get("casks") or []

    cfg_arches = list(platforms.keys())
    arches = args.arch or cfg_arches
    want = set(args.formula) if args.formula else None
    want_casks = set(args.cask) if args.cask else None
    # A --formula/--cask filter means "only that kind"; otherwise do both.
    do_formulae = not (args.formula or args.cask) or args.formula is not None
    do_casks = not (args.formula or args.cask) or args.cask is not None

    print(f"output   : {out_root}")
    print(f"arches   : {', '.join(arches)}")
    print(f"formulae : {len(formulae)}   casks : {len(casks)}\n")

    manifest = {"source": "homebrew", "entries": []}
    n_ok = n_fail = 0
    if not do_formulae:
        formulae = []

    for arch in arches:
        akey = ARCH_ALIASES.get(arch.lower(), arch.lower())
        tags = platforms.get(arch) or platforms.get(akey) or DEFAULT_PLATFORMS.get(akey)
        if not tags:
            print(f"[{arch}] no bottle tags configured; skipping")
            continue
        if isinstance(tags, str):
            tags = [tags]

        for entry in formulae:
            formula = entry.get("name")
            if not formula:
                print("[skip] formula entry without a `name:`")
                continue
            if want and formula not in want:
                continue

            tag_label = f"{formula}/{arch}"
            try:
                bins = normalise_binaries(entry)

                # Skip when every predictable output is already on disk.
                if not args.force and not args.dry_run:
                    outs = []
                    predictable = True
                    for b in bins:
                        tmpl = b["name"] or name_tmpl
                        base = posixpath.basename(b["path"].rstrip("/"))
                        if any(c in b["path"] for c in "*?[") and \
                                any(k in tmpl for k in ("{basename", "{stem", "{ext")):
                            predictable = False
                            break
                        outs.append(os.path.join(
                            out_root, render_name(tmpl, formula=formula,
                                                  arch=arch, basename=base)))
                    if predictable and outs and all(os.path.exists(p) for p in outs):
                        print(f"[{tag_label}] cached ({len(outs)} file(s))")
                        n_ok += 1
                        continue

                pinned = entry.get("version")
                version, used_tag, url, want_sha = resolve_bottle(
                    formula, tags, pinned=pinned)

                if args.dry_run:
                    print(f"[{tag_label}] {version} @ {used_tag}\n         {url}")
                    n_ok += 1
                    continue

                blob = download_bottle(url)
                if want_sha:
                    got = hashlib.sha256(blob).hexdigest()
                    if got != want_sha:
                        raise FetchError(
                            f"bottle sha256 mismatch (got {got[:12]}…, "
                            f"want {want_sha[:12]}…)")

                tar = tarfile.open(fileobj=io.BytesIO(gzip.decompress(blob)), mode="r:")
                extracted = extract_binaries(tar, [b["path"] for b in bins])
                for b in bins:
                    npat = _norm(b["path"])
                    if not any(fnmatch.fnmatchcase(k, npat) or (
                            "/" not in b["path"].strip("/")
                            and fnmatch.fnmatchcase(posixpath.basename(k), npat))
                               for k in extracted):
                        print(f"[{tag_label}] WARNING: no member matched '{b['path']}'")

                explicit = {b["path"]: b["name"] for b in bins if b["name"]}
                os.makedirs(out_root, exist_ok=True)
                for member_name, (src_name, data) in sorted(extracted.items()):
                    basename = posixpath.basename(member_name)
                    chosen = None
                    for pat, nm in explicit.items():
                        np = _norm(pat)
                        if fnmatch.fnmatchcase(member_name, np) or (
                                "/" not in pat.strip("/")
                                and fnmatch.fnmatchcase(basename, np)):
                            chosen = nm
                            break
                    fname = render_name(chosen or name_tmpl, formula=formula,
                                        arch=arch, basename=basename)
                    dest = os.path.join(out_root, fname)
                    with open(dest, "wb") as fh:
                        fh.write(data)
                    sha = hashlib.sha256(data).hexdigest()
                    rel = os.path.relpath(dest, out_root)
                    print(f"[{tag_label}] {member_name}  ->  {rel}  ({len(data):,} B)")
                    manifest["entries"].append({
                        "formula": formula, "arch": arch, "version": version,
                        "bottle_tag": used_tag, "member": src_name, "output": rel,
                        "sha256": sha, "bottle_url": url, "bottle_sha256": want_sha,
                    })
                n_ok += 1

            except FetchError as exc:
                print(f"[{tag_label}] FAILED: {exc}")
                n_fail += 1
            except Exception as exc:  # noqa: BLE001
                print(f"[{tag_label}] ERROR: {exc}")
                n_fail += 1

    # Casks (desktop apps). One artifact (usually a universal binary) is
    # downloaded once and sliced for each arch, so the download+extract is
    # cached by URL across arches.
    dl_cache: dict[str, tuple[str, bytes]] = {}  # url -> (exe_name, macho_bytes)
    for entry in (casks if do_casks else []):
        token = entry.get("name") if isinstance(entry, dict) else entry
        if not token:
            print("[skip] cask entry without a `name:`")
            continue
        if want_casks and token not in want_casks:
            continue
        exe_override = entry.get("executable") if isinstance(entry, dict) else None
        safe = token.replace("@", "").replace("/", "_")
        for arch in arches:
            akey = ARCH_ALIASES.get(arch.lower(), arch.lower())
            label = f"{token}/{arch}"
            dest = os.path.join(out_root, f"{safe}_cask_{arch}_bin")
            try:
                if not args.force and not args.dry_run and os.path.exists(dest):
                    print(f"[{label}] cached")
                    n_ok += 1
                    continue
                version, url, want_sha, app = resolve_cask(token, akey)
                if args.dry_run:
                    print(f"[{label}] {version}\n         {url}")
                    n_ok += 1
                    continue
                if url in dl_cache:
                    exe_name, macho = dl_cache[url]
                else:
                    blob = http_get(url, timeout=600)
                    if want_sha and len(want_sha) == 64 and all(
                            c in "0123456789abcdef" for c in want_sha):
                        got = hashlib.sha256(blob).hexdigest()
                        if got != want_sha:
                            raise FetchError(
                                f"artifact sha256 mismatch (got {got[:12]}…, "
                                f"want {want_sha[:12]}…)")
                    exe_name, macho = app_main_macho(blob, url, exe_override, app)
                    dl_cache[url] = (exe_name, macho)
                thin = slice_macho(macho, akey)
                if thin is None:
                    print(f"[{label}] WARNING: no {akey} slice in {exe_name!r}")
                    continue
                os.makedirs(out_root, exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(thin)
                rel = os.path.relpath(dest, out_root)
                print(f"[{label}] {app or '?'}:{exe_name}  ->  {rel}  ({len(thin):,} B)")
                manifest["entries"].append({
                    "cask": token, "arch": arch, "version": version,
                    "app": app, "executable": exe_name, "output": rel,
                    "sha256": hashlib.sha256(thin).hexdigest(),
                    "source_url": url, "artifact_sha256": want_sha,
                })
                n_ok += 1
            except FetchError as exc:
                print(f"[{label}] FAILED: {exc}")
                n_fail += 1
            except Exception as exc:  # noqa: BLE001
                print(f"[{label}] ERROR: {exc}")
                n_fail += 1

    if not args.dry_run:
        os.makedirs(out_root, exist_ok=True)
        mpath = os.path.join(out_root, "manifest.json")
        with open(mpath, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
        print(f"\nmanifest : {mpath}  ({len(manifest['entries'])} binaries)")

    print(f"done: {n_ok} ok, {n_fail} failed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())

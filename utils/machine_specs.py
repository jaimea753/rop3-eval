#!/usr/bin/env python3
"""
Benchmark-machine specifications: detection, storage and HTML rendering.

The ropchains experiment publishes wall-clock timings, which are meaningless
without the machine that produced them. This module is the single place that
knows what a "machine" is:

  * detect()      -- best-effort hardware/OS probe of the current host
  * machine_id()  -- a stable, *hashed* identifier for this host, used both as
                     the machine.yaml `id` and as part of the benchmark cache
                     key (see utils/benchcache.py)
  * load()        -- read machine.yaml (hand-written fields are authoritative)
  * render_html() -- the "Benchmark environment" panel for utils/build_site.py

Stdlib + PyYAML only, so run-experiments.py can import it without pulling in
the plotting stack. Every probe degrades to None instead of raising: a machine
file with holes in it is still better than no provenance at all.

    python utils/machine_specs.py --print            # show what is detected
    python utils/machine_specs.py --write            # (re)generate machine.yaml
"""
import argparse
import datetime
import hashlib
import html
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MACHINE_FILE = REPO_ROOT / "machine.yaml"

# Fields a human writes; detection never overwrites them when regenerating over
# an existing file (see detect(merge_into=...)).
HAND_WRITTEN = ("label", "notes")


# --- probes ----------------------------------------------------------------

def _read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _run(cmd):
    """Run a probe command, returning its stripped stdout or None."""
    if not shutil.which(cmd[0]):
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


def machine_id():
    """Stable short identifier for this host.

    /etc/machine-id is a system secret by convention (it is used to derive
    application-specific IDs), and this value gets committed to a public repo,
    so it is hashed rather than stored raw. Falls back through dbus' copy to
    the hostname, which is stable enough to key a local cache on.
    """
    raw = (_read_text("/etc/machine-id")
           or _read_text("/var/lib/dbus/machine-id")
           or _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
           or platform.node())
    raw = (raw or "unknown").strip()
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _cpu():
    """{model, arch, cores, threads} -- Linux /proc first, macOS sysctl after."""
    info = {"model": None, "arch": platform.machine() or None,
            "cores": None, "threads": os.cpu_count()}

    cpuinfo = _read_text("/proc/cpuinfo")
    if cpuinfo:
        model = re.search(r"^model name\s*:\s*(.+)$", cpuinfo, re.M)
        if not model:   # aarch64/riscv64 Linux have no 'model name'
            model = re.search(r"^(?:Model|Hardware|uarch)\s*:\s*(.+)$", cpuinfo, re.M)
        if model:
            info["model"] = model.group(1).strip()
        # Physical cores = distinct (socket, core) pairs; threads = logical CPUs.
        pairs = set(zip(re.findall(r"^physical id\s*:\s*(\d+)$", cpuinfo, re.M),
                        re.findall(r"^core id\s*:\s*(\d+)$", cpuinfo, re.M)))
        processors = len(re.findall(r"^processor\s*:", cpuinfo, re.M))
        info["cores"] = len(pairs) or processors or None
        info["threads"] = processors or info["threads"]
    else:
        info["model"] = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
        cores = _run(["sysctl", "-n", "hw.physicalcpu"])
        if cores and cores.isdigit():
            info["cores"] = int(cores)

    return info


def _memory():
    """{total_gib} -- binary gigabytes, as every tool on the box reports RAM."""
    meminfo = _read_text("/proc/meminfo")
    total_kib = None
    if meminfo:
        m = re.search(r"^MemTotal:\s*(\d+) kB$", meminfo, re.M)
        if m:
            total_kib = int(m.group(1))
    else:
        raw = _run(["sysctl", "-n", "hw.memsize"])
        if raw and raw.isdigit():
            total_kib = int(raw) // 1024

    if total_kib is None:
        return {"total_gib": None}
    return {"total_gib": round(total_kib / (1024 * 1024), 1)}


def _os():
    """{name, version, kernel} from /etc/os-release, falling back to platform."""
    name = version = None
    release = _read_text("/etc/os-release")
    if release:
        fields = {}
        for line in release.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"')
        name = fields.get("NAME") or None
        version = fields.get("VERSION") or fields.get("VERSION_ID") or None
        build = fields.get("BUILD_ID")
        # Rolling/immutable distros (NixOS, Arch) pin far more precisely by
        # build than by version, and that is the reproducibility-relevant bit.
        if build and version and build not in version:
            version = f"{version} [build {build}]"
    if not name:
        name = platform.system() or None
        version = platform.mac_ver()[0] or platform.release() or None
    return {"name": name, "version": version, "kernel": platform.release() or None}


def _virtualization():
    """Hypervisor name, 'none' on bare metal, or None when undetectable."""
    virt = _run(["systemd-detect-virt"])
    if virt:
        return virt
    cpuinfo = _read_text("/proc/cpuinfo") or ""
    if re.search(r"^flags\s*:.*\bhypervisor\b", cpuinfo, re.M):
        return "unknown hypervisor"
    return None


def detect(merge_into=None):
    """Probe this host and return a machine-spec mapping.

    `merge_into` is an already-loaded spec whose hand-written fields (label,
    notes) are carried over, so regenerating never eats the prose a human
    added.
    """
    spec = {
        "id": machine_id(),
        "label": platform.node() or "unnamed machine",
        "collected": datetime.date.today().isoformat(),
        "cpu": _cpu(),
        "memory": _memory(),
        "os": _os(),
        "virtualization": _virtualization(),
        "python": platform.python_version(),
        "notes": None,
    }
    previous = dict(merge_into or {})
    for field in HAND_WRITTEN:
        if previous.get(field):
            spec[field] = previous[field]
    return spec


# --- storage ---------------------------------------------------------------

class _BlockDumper(yaml.SafeDumper):
    """SafeDumper that keeps multi-line strings readable as literal blocks.

    The default representer turns a `notes:` paragraph into a quoted scalar
    with a blank line between every wrapped line, which is unpleasant both in
    machine.yaml and in the run-meta.yaml that embeds it.
    """


def _represent_str(dumper, data):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_BlockDumper.add_representer(str, _represent_str)


def dump_yaml(data, stream=None):
    """yaml.dump with this project's formatting: key order kept, blocks intact."""
    return yaml.dump(data, stream, Dumper=_BlockDumper, sort_keys=False,
                     allow_unicode=True, default_flow_style=False)


def load(path=DEFAULT_MACHINE_FILE):
    """Read a machine-spec YAML. Returns None when the file is absent.

    The file -- not detection -- is authoritative: a run on a laptop may well
    describe the bare-metal rig the numbers actually came from.
    """
    path = Path(path)
    if not path.is_file():
        return None
    try:
        spec = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"[WARN] could not read {path}: {exc}", file=sys.stderr)
        return None
    if not isinstance(spec, dict):
        print(f"[WARN] {path}: expected a YAML mapping", file=sys.stderr)
        return None
    return spec


FILE_HEADER = """\
# Benchmark machine of record -- the host that produced results/.
#
# Regenerate with `python utils/machine_specs.py --write` (`--print` to just
# look). Detection fills the hardware/OS fields; `label` and `notes` are
# hand-written and survive regeneration, as do these comments, which are
# re-emitted from utils/machine_specs.py on every write.
#
# The file is authoritative, not the detector: edit any value by hand if the
# numbers actually came off a different box than the one you are typing on.
# utils/build_site.py renders it as the "Benchmark environment" panel on the
# results site.
"""

# Explanations emitted above each top-level key, so the generated file
# documents itself and there is no separate template to keep in sync.
FIELD_DOCS = {
    "id": ("Stable short identifier: sha256(/etc/machine-id)[:12], hashed because\n"
           "this file is committed. Also part of the benchmark cache key (see\n"
           "utils/benchcache.py), so pinning it by hand lets two checkouts on the\n"
           "same machine -- or two machines you consider interchangeable -- share\n"
           "a cache."),
    "label": "Human-readable name for the machine, shown on the site. Hand-written.",
    "collected": "Date these specs were collected (ISO 8601).",
    "cpu": ("model/arch come from /proc/cpuinfo, `cores` counts physical cores and\n"
            "`threads` logical CPUs -- the pool's `workers` compete for those."),
    "memory": ("Binary GiB. Workers cap themselves at min(16 GiB, 75% of RAM), so a\n"
               "small number here explains OOM-degraded rows."),
    "os": "Distribution name/version from /etc/os-release, plus `uname -r`.",
    "virtualization": ("Hypervisor name, 'none' on bare metal, null when undetectable.\n"
                       "Virtualized timings are noisier -- worth stating plainly."),
    "python": "Python running the driver.",
    "notes": ("Free text: anything a reader needs in order to judge the timings.\n"
              "Hand-written."),
}


def _with_comments(body):
    """Interleave FIELD_DOCS into a YAML dump, above each top-level key."""
    lines = []
    for line in body.splitlines():
        key = line.split(":", 1)[0]
        if line[:1] not in (" ", "#", "") and key in FIELD_DOCS:
            if lines:
                lines.append("")
            lines.extend(f"# {c}" for c in FIELD_DOCS[key].split("\n"))
        lines.append(line)
    return "\n".join(lines) + "\n"


def dump(spec, path=DEFAULT_MACHINE_FILE):
    """Write a machine-spec YAML: documented, in the documented key order."""
    path = Path(path)
    path.write_text(FILE_HEADER + "\n" + _with_comments(dump_yaml(spec)), encoding="utf-8")
    return path


# --- rendering -------------------------------------------------------------

def _fmt_cpu(cpu):
    if not cpu:
        return None
    model = cpu.get("model") or "unknown CPU"
    bits = []
    cores, threads = cpu.get("cores"), cpu.get("threads")
    if cores:
        bits.append(f"{cores} core{'s' if cores != 1 else ''}")
    if threads and threads != cores:
        bits.append(f"{threads} threads")
    if cpu.get("arch"):
        bits.append(cpu["arch"])
    return f"{model} ({', '.join(bits)})" if bits else model


def _rows(spec):
    """(label, value) pairs for the spec table, skipping anything unknown."""
    cpu = _fmt_cpu(spec.get("cpu"))
    memory = (spec.get("memory") or {}).get("total_gib")
    os_info = spec.get("os") or {}
    os_str = " ".join(str(v) for v in (os_info.get("name"), os_info.get("version")) if v)
    virt = spec.get("virtualization")
    if virt == "none":
        virt = "bare metal"

    candidates = [
        ("CPU", cpu),
        ("Memory", f"{memory} GiB" if memory else None),
        ("OS", os_str or None),
        ("Kernel", os_info.get("kernel")),
        ("Virtualization", virt),
        ("Python", spec.get("python")),
        ("Machine ID", spec.get("id")),
    ]
    return [(k, str(v)) for k, v in candidates if v]


def render_html(spec, heading="Benchmark environment"):
    """The environment panel for the results site. '' when there is no spec."""
    if not spec:
        return ""

    label = spec.get("label") or "Benchmark machine"
    collected = spec.get("collected")
    sub = f' <span class="muted">· specs collected {html.escape(str(collected))}</span>' if collected else ""

    cells = "".join(
        f"<div><dt>{html.escape(k)}</dt><dd>{html.escape(v)}</dd></div>"
        for k, v in _rows(spec)
    )
    notes = spec.get("notes")
    notes_html = f'<p class="machine-notes">{html.escape(str(notes).strip())}</p>' if notes else ""

    return (
        '<section class="machine">\n'
        f"<h2>{html.escape(heading)}</h2>\n"
        f'<p class="machine-label"><strong>{html.escape(str(label))}</strong>{sub}</p>\n'
        f'<dl class="specs">{cells}</dl>\n'
        f"{notes_html}\n"
        "</section>\n"
    )


def summary_line(spec):
    """One-line description, for per-experiment provenance notes."""
    if not spec:
        return ""
    parts = [str(spec.get("label") or spec.get("id") or "unknown machine")]
    cpu = _fmt_cpu(spec.get("cpu"))
    if cpu:
        parts.append(cpu)
    memory = (spec.get("memory") or {}).get("total_gib")
    if memory:
        parts.append(f"{memory} GiB RAM")
    return " — ".join(parts)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", nargs="?", const=str(DEFAULT_MACHINE_FILE), default=None,
                    metavar="FILE",
                    help=f"write detected specs to FILE (default: {DEFAULT_MACHINE_FILE.name})")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="print detected specs without writing anything")
    args = ap.parse_args(argv)

    target = Path(args.write) if args.write else DEFAULT_MACHINE_FILE
    spec = detect(merge_into=load(target))

    if args.write and not args.print_only:
        dump(spec, target)
        print(f"Wrote {target}")
    else:
        print(dump_yaml(spec), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())

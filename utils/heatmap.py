#!/usr/bin/env python3
"""
Unified heatmap generator for run-experiments.py result TSVs.

Reads a result TSV (rows = libraries/binaries, columns = operations or ROP
chains, cells = gadget counts) and renders a seaborn heatmap. Each operation
column is min-max normalized on its own, so colour shows relative abundance
*within* an operation; the raw count is printed in every cell.

By default it opens a live, interactive preview window (Wayland-native when a
Qt/GTK toolkit is present). Pass --pdf (or -o FILE) to write a file instead.

    python utils/heatmap.py results_presence_rop_libc.tsv            # live preview
    python utils/heatmap.py results_presence_rop_libc.tsv --pdf      # -> heatmap-results/<name>.pdf
    python utils/heatmap.py results.tsv -o out.svg --show            # save AND preview
    python utils/heatmap.py results.tsv --backend GTK4Agg            # force a backend

Styling follows the former heatmap_generator scripts (seaborn, `inferno`, per
-column normalization, `k`-abbreviated labels, transparent background). Rows
are labelled and ordered differently depending on the source: ops-mode output
(one row per pre-named per-arch library build, e.g. the libc corpus) has its
library names cleaned and prettified, ordered by OS then architecture;
presence-mode output (has an 'arch' column, and may hold several unrelated
binaries with no arch/OS naming convention to parse) is labelled with the
actual binary name plus rop3's own detected architecture, ordered by that
architecture then by name.

If given a bare filename that isn't found, the results directory
(default: heatmap-results/, override with --results-dir) is searched too, and
that is also where --pdf output lands.
"""
import os
import re
import sys
import argparse

import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns

DEFAULT_RESULTS_DIR = "heatmap-results"
ARCH_COL = "arch"                   # reserved column emitted by presence mode

# GUI backends tried, in order, for the live preview. QtAgg (PyQt6/PySide6) and
# the GTK backends speak Wayland natively; TkAgg falls back through XWayland.
GUI_BACKENDS = ["QtAgg", "GTK4Agg", "GTK3Agg", "TkAgg"]

# --- Library-name normalization -------------------------------------------
# OS display order (prefix match, so 'fedora43' sorts as 'fedora').
OS_ORDER = [
    "debian", "ubuntu", "fedora", "slackware", "void_glibc", "void_musl",
    "archlinux", "freebsd", "openbsd", "netbsd", "macos",
]
OS_PRETTY = {
    "debian": "Debian", "ubuntu": "Ubuntu", "fedora": "Fedora",
    "slackware": "Slackware", "void_glibc": "Void (glibc)",
    "void_musl": "Void (musl)", "archlinux": "Arch Linux",
    "freebsd": "FreeBSD", "openbsd": "OpenBSD", "netbsd": "NetBSD",
    "macos": "macOS",
}

# Architecture tokens -> (order index, display). rop3 targets four ISAs; the
# corpus tags binaries with any of these aliases.
ARCH_CANON = [
    (["i386", "x86", "x86_32", "ia32"],          "x86 (32-bit)"),
    (["amd64", "x86_64", "x86-64", "x64"],        "x86-64"),
    (["aarch64", "arm64"],                        "AArch64"),
    (["riscv64", "riscv", "rv64"],                "RISC-V"),
]
# token -> (arch_order_idx, display), longest token first so 'x86_64' wins
# over 'x86' when both would match.
_ARCH_LOOKUP = sorted(
    ((tok, (idx, disp)) for idx, (toks, disp) in enumerate(ARCH_CANON) for tok in toks),
    key=lambda kv: len(kv[0]), reverse=True,
)
_LIBC_SUFFIX = re.compile(r"_libc(?:\.so(?:\.\d+)?|\.dylib|\.dll)?$", re.IGNORECASE)


def _pretty_arch(raw_arch):
    """(order_idx, display) for a raw architecture string as reported by
    rop3's own detection (the 'arch' column) -- not guessed from a filename.
    Unrecognized values (e.g. 'unknown'/'unsupported') pass through as-is,
    sorted after every recognized ISA."""
    s = str(raw_arch).lower()
    for tok, (idx, disp) in _ARCH_LOOKUP:
        if tok in s:
            return idx, disp
    return len(ARCH_CANON), str(raw_arch)


def _split_name(raw):
    """(os_part, arch_idx, pretty_label) for a raw library/binary name."""
    name = _LIBC_SUFFIX.sub("", str(raw))

    arch_idx, arch_disp = len(ARCH_CANON), None
    os_part = name
    for tok, (idx, disp) in _ARCH_LOOKUP:
        m = re.search(rf"(?:^|_){re.escape(tok)}(?:_|$)", name)
        if m:
            arch_idx, arch_disp = idx, disp
            os_part = (name[:m.start()] + name[m.end():]).strip("_")
            break

    os_key = os_part
    os_idx, os_disp = len(OS_ORDER), os_part
    for i, os_name in enumerate(OS_ORDER):
        if os_part.startswith(os_name):
            os_idx = i
            version = os_part[len(os_name):].strip("_")
            os_disp = f"{OS_PRETTY[os_name]} {version}".strip()
            break

    label = f"{os_disp} — {arch_disp}" if arch_disp else os_disp
    return (os_idx, os_key), arch_idx, label


def load_matrix(path):
    """Read a result TSV into a numeric count matrix.

    Presence-mode output (has the reserved 'arch' column) may hold several
    unrelated binaries -- not just per-arch builds of one curated library --
    whose filenames carry no OS/arch naming convention to parse (e.g. `ls`,
    `cat`, a bundle folder named after its own architecture). Guessing the
    arch from the name there would silently lose it, so rows are instead
    labelled with the actual binary name plus rop3's own detected
    architecture, and ordered by that detected arch then by name.

    Otherwise (ops-mode output, one row per pre-named per-arch library build,
    e.g. the libc corpus) there is no detected-arch column to trust, so rows
    are ordered by OS then architecture and relabelled with prettified names
    parsed from the curated naming convention, as before.
    """
    df = pd.read_csv(path, sep="\t", index_col=0)

    if ARCH_COL in df.columns:
        arch_col = df[ARCH_COL]
        df = df.drop(columns=[ARCH_COL])
        df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
        if df.empty or df.shape[1] == 0:
            raise ValueError(f"{path!r}: no numeric columns to plot.")

        keys = {name: _pretty_arch(arch_col[name]) for name in df.index}
        order = sorted(df.index, key=lambda n: (keys[n][0], n))
        df = df.loc[order]
        df.index = [f"{n} — {keys[n][1]}" for n in order]
        return df

    # Everything left is a count / boolean; blanks and stray text -> 0.
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
    if df.empty or df.shape[1] == 0:
        raise ValueError(f"{path!r}: no numeric columns to plot.")

    keys = {name: _split_name(name) for name in df.index}
    order = sorted(df.index, key=lambda n: (keys[n][0][0], keys[n][1], keys[n][0][1]))
    df = df.loc[order]
    df.index = [keys[n][2] for n in order]
    return df


def make_heatmap(df, *, cmap="inferno", title=None):
    """Render the count matrix (per-column normalized) to a Figure."""
    df_norm = df.apply(
        lambda c: (c - c.min()) / (c.max() - c.min())
        if (c.max() - c.min()) != 0 else c * 0.0
    )
    labels = df.map(lambda x: f"{x/1000:.0f}k" if x >= 1000 else f"{x:g}")

    height = max(4.0, 0.42 * df.shape[0] + 1.5)
    width = max(8.0, 0.7 * df.shape[1] + 3.0)
    fig = plt.figure(figsize=(width, height))
    fig.patch.set_alpha(0)
    ax = fig.add_subplot(111)
    ax.patch.set_alpha(0)

    sns.heatmap(
        df_norm, annot=labels, fmt="", cmap=cmap, ax=ax,
        cbar=True, cbar_kws={"label": "per-operation normalized (0–1)"},
        linewidths=0.5, linecolor="white", annot_kws={"fontsize": 8},
    )
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right")
    ax.set_yticklabels(ax.get_yticklabels(), rotation=0)
    ax.set_xlabel(df.columns.name or "operation")
    ax.set_ylabel("")
    ax.tick_params(length=0)
    if title:
        ax.set_title(title, pad=12, fontsize=13, fontweight="bold")

    fig.tight_layout()
    return fig


def activate_gui_backend(preferred=None):
    """Switch matplotlib to an interactive, Wayland-friendly backend. Returns
    the backend name, or None if none could be loaded (headless / no toolkit)."""
    for name in ([preferred] if preferred else []) + GUI_BACKENDS:
        if not name:
            continue
        try:
            plt.switch_backend(name)
            return name
        except Exception:
            continue
    return None


def _resolve_input(path, results_dir):
    if os.path.isfile(path):
        return path
    alt = os.path.join(results_dir, path)
    if os.path.isfile(alt):
        return alt
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Render a heatmap from a run-experiments.py result TSV. "
                    "Live preview by default; --pdf/-o to save a file.")
    ap.add_argument("tsv", help="result TSV (searched in --results-dir if not "
                                 "found as given)")
    ap.add_argument("--pdf", action="store_true",
                    help=f"save a PDF to {DEFAULT_RESULTS_DIR}/<name>.pdf "
                         "instead of previewing")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="save to FILE (format from extension: .pdf/.png/.svg)")
    ap.add_argument("--show", action="store_true",
                    help="also open the live preview when saving")
    ap.add_argument("--backend", metavar="NAME",
                    help="force a matplotlib GUI backend (e.g. QtAgg, GTK4Agg, "
                         "TkAgg)")
    ap.add_argument("--cmap", default="inferno",
                    help="matplotlib/seaborn colormap (default: inferno)")
    ap.add_argument("--title", help="plot title")
    ap.add_argument("--dpi", type=int, default=150,
                    help="raster DPI for .png output (default: 150)")
    ap.add_argument("--results-dir", default=DEFAULT_RESULTS_DIR,
                    help=f"directory holding result TSVs and where --pdf writes "
                         f"(default: {DEFAULT_RESULTS_DIR})")
    args = ap.parse_args(argv)

    src = _resolve_input(args.tsv, args.results_dir)
    if src is None:
        print(f"ERROR: {args.tsv!r}: no such file (also looked in "
              f"{args.results_dir!r})", file=sys.stderr)
        return 1

    try:
        df = load_matrix(src)
    except Exception as exc:
        print(f"ERROR: could not read {src!r}: {exc}", file=sys.stderr)
        return 1

    out = args.output
    if args.pdf and not out:
        os.makedirs(args.results_dir, exist_ok=True)
        stem = os.path.splitext(os.path.basename(src))[0]
        out = os.path.join(args.results_dir, f"{stem}.pdf")

    saving = out is not None
    previewing = args.show or not saving

    backend = None
    if previewing:
        backend = activate_gui_backend(args.backend)
        if backend is None:
            print("  [WARN] no interactive GUI backend available (headless or "
                  "no Qt/GTK/Tk); use --pdf to write a file, or install a "
                  "toolkit (PyQt6 is in requirements.txt).", file=sys.stderr)
            previewing = False
            if not saving:
                return 1

    fig = make_heatmap(df, cmap=args.cmap, title=args.title)
    print(f"Rendered {df.shape[0]} libraries × {df.shape[1]} columns from "
          f"{os.path.basename(src)}")

    if saving:
        parent = os.path.dirname(out)
        if parent:
            os.makedirs(parent, exist_ok=True)
        fig.savefig(out, dpi=args.dpi, transparent=True,
                    bbox_inches="tight", pad_inches=0.05)
        print(f"Wrote {out}")

    if previewing:
        print(f"Opening live preview [{backend}] — close the window to exit.")
        plt.show()

    return 0


if __name__ == "__main__":
    sys.exit(main())

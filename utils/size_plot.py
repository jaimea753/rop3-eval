#!/usr/bin/env python3
"""
Binary size vs. gadget count curves for run-experiments.py count matrices.

Reads an ops- or presence-mode result TSV (rows = binaries, columns =
operations, cells = gadget counts) together with each binary's size on disk
and renders:

  * one figure per operation -- every binary as a point (x = bytes on disk,
    y = gadgets found for that operation, both log) coloured and shaped by
    architecture, with a robust power-law trend `count ∝ size^b` fitted by
    Theil–Sen in log–log space. Binaries where the operation is absent sit on
    a dashed "none" floor below the axis (a hollow marker), so they are never
    silently dropped;
  * one aggregate figure folding every operation into a single score per
    binary: each operation's column is first divided by its own median count
    (so a 20 000-gadget `pivot` column weighs the same as a 50-gadget `neg`
    one), the per-operation values are winsorized at the 5th/95th percentile
    to attenuate anomalous binaries, and the binary's score is the *median*
    of those relative abundances (1.0 = a typical binary of the corpus). A
    thin bar shows the interquartile range across operations, and the same
    Theil–Sen trend is drawn.

Sizes come from `library_bytes` in the run-meta.yaml beside the TSV
(run-experiments.py and compare-tools.py record it, because the corpus is
gitignored and the site build cannot stat it), with --binaries-dir as a
fallback for runs that predate the key. --write-sizes backfills the sizes
found that way into run-meta.yaml, so the site build sees them too.

Same output conventions as utils/heatmap.py: live preview by default, --pdf
or -o FILE to save. One file is written per figure, named
`<name>_size_<op>.<ext>` / `<name>_size_aggregate.<ext>`.

    python utils/size_plot.py results/libc_tfg_rop/results_rop_libc.tsv              # live preview
    python utils/size_plot.py results/libc_tfg_rop/results_rop_libc.tsv --pdf        # -> heatmap-results/
    python utils/size_plot.py results.tsv -o out.png --op pivot --op mov             # two operations
    python utils/size_plot.py results.tsv --binaries-dir binaries/libc --write-sizes # backfill run-meta
"""
import os
import sys
import math
import argparse

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FixedLocator, FuncFormatter, LogLocator, NullLocator

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from heatmap import (  # noqa: E402
    ARCH_CANON, ARCH_COL, DEFAULT_RESULTS_DIR, _pretty_arch, _resolve_input,
    _split_name, activate_gui_backend,
)

INK, MUTED, GRID, AXIS = "#0b0b0b", "#52514e", "#e1e0d9", "#c3c2b7"
UNKNOWN_ARCH = "unknown"
# Fixed colour + marker per ISA, in canonical order, so an architecture keeps
# its identity across every figure whether or not the others are present.
# Shape is the second channel: four hues on one scatter is past what colour
# alone separates reliably.
ARCH_STYLE = {
    "x86 (32-bit)": ("#2a78d6", "o"),
    "x86-64":       ("#eb6834", "s"),
    "AArch64":      ("#1baf7a", "D"),
    "RISC-V":       ("#eda100", "^"),
}
OTHER_STYLE = ("#898781", "x")
WINSOR = (0.05, 0.95)       # per-operation clip quantiles for the aggregate
MIN_FIT_POINTS = 3          # Theil–Sen needs a few distinct sizes to mean anything
MIN_OP_POINTS = 3           # an operation present in fewer binaries has no median to scale by


# --- Loading -----------------------------------------------------------------
def load_counts(tsv):
    """(counts, arch): the numeric count matrix (index = raw library names,
    columns = operations) and a Series mapping each library to its display
    architecture -- rop3's own detection when the TSV has an `arch` column
    (presence mode), the curated filename convention otherwise (ops mode)."""
    df = pd.read_csv(tsv, sep="\t", index_col=0)
    if ARCH_COL in df.columns:
        arch = df[ARCH_COL].map(lambda a: _pretty_arch(a)[1])
        df = df.drop(columns=[ARCH_COL])
    else:
        arch = pd.Series({name: _split_name(name)[1] for name in df.index}).map(
            lambda idx: ARCH_CANON[idx][1] if idx < len(ARCH_CANON) else UNKNOWN_ARCH)
    counts = df.apply(pd.to_numeric, errors="coerce").fillna(0)
    if counts.empty or counts.shape[1] == 0:
        raise ValueError(f"{tsv!r}: no numeric columns to plot.")
    return counts, arch.reindex(counts.index).fillna(UNKNOWN_ARCH)


def load_sizes(tsv, binaries_dir=None):
    """{library: bytes}. Read from `library_bytes` in the run-meta.yaml beside
    the TSV (run-experiments.py / compare-tools.py record it; the corpus itself
    is gitignored), then filled in from files under *binaries_dir* for anything
    missing there (a subfolder is a bundle: all its files, one target). A
    zero size -- an empty placeholder left by a failed download -- is not a
    size and is left out."""
    sizes = {}
    meta = _meta_path(tsv)
    if os.path.isfile(meta):
        import yaml
        with open(meta, encoding="utf-8") as f:
            sizes.update((yaml.safe_load(f) or {}).get("library_bytes") or {})
    if binaries_dir and os.path.isdir(binaries_dir):
        for name in os.listdir(binaries_dir):
            path = os.path.join(binaries_dir, name)
            if name in sizes:
                continue
            if os.path.isfile(path):
                sizes[name] = os.path.getsize(path)
            elif os.path.isdir(path):
                sizes[name] = sum(os.path.getsize(os.path.join(path, f))
                                  for f in os.listdir(path)
                                  if os.path.isfile(os.path.join(path, f)))
    return {name: int(n) for name, n in sizes.items() if n and int(n) > 0}


def _meta_path(tsv):
    return os.path.join(os.path.dirname(os.path.abspath(tsv)), "run-meta.yaml")


def write_sizes(tsv, sizes, libraries):
    """Backfill `library_bytes` for *libraries* into the run-meta.yaml beside
    the TSV (created if absent), keeping the file's key order. Returns the
    number of entries written."""
    import yaml
    try:
        import machine_specs
        dump = machine_specs.dump_yaml
    except ImportError:                      # pragma: no cover
        def dump(data, stream):
            yaml.safe_dump(data, stream, sort_keys=False, allow_unicode=True)
    path = _meta_path(tsv)
    meta = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            meta = yaml.safe_load(f) or {}
    known = {lib: int(sizes[lib]) for lib in libraries if sizes.get(lib)}
    if not known:
        return 0
    # Keep provenance keys first and the machine block last, as the drivers
    # write them, by inserting the sizes just before `machine`.
    items = [(k, v) for k, v in meta.items() if k not in ("library_bytes", "machine")]
    items.append(("library_bytes", dict(sorted(known.items()))))
    if "machine" in meta:
        items.append(("machine", meta["machine"]))
    with open(path, "w", encoding="utf-8") as f:
        dump(dict(items), f)
    return len(known)


# --- Statistics ---------------------------------------------------------------
def theil_sen(x, y):
    """(slope, intercept) of y ≈ slope·x + intercept by Theil–Sen: the median
    of all pairwise slopes, then the median residual intercept. Robust to a
    third of the points being outliers. None with too few distinct x."""
    x, y = np.asarray(x, float), np.asarray(y, float)
    if len(x) < MIN_FIT_POINTS or len(np.unique(x)) < MIN_FIT_POINTS:
        return None
    i, j = np.triu_indices(len(x), k=1)
    dx = x[j] - x[i]
    keep = dx != 0
    slope = float(np.median((y[j] - y[i])[keep] / dx[keep]))
    return slope, float(np.median(y - slope * x))


def relative_abundance(counts, winsor=WINSOR, min_points=MIN_OP_POINTS):
    """Fold every operation into one score per binary.

    Each column is divided by the median of its *positive* counts, so every
    operation is measured in "multiples of a typical binary" regardless of how
    many gadgets it yields in absolute terms; an operation present in fewer
    than *min_points* binaries has no such typical value and is left out.
    Each relative column is then winsorized at *winsor* (clipped to its own
    5th–95th percentile), which pulls in anomalous binaries without dropping
    them. Returns a DataFrame indexed like *counts* with `score` (the median
    across operations), `q25`/`q75` (interquartile range across operations)
    and `ops` (how many operations contributed)."""
    rel = {}
    for op in counts.columns:
        col = counts[op].astype(float)
        positive = col[col > 0]
        if len(positive) < min_points:
            continue
        scaled = col / float(positive.median())
        lo, hi = scaled.quantile(winsor[0]), scaled.quantile(winsor[1])
        rel[op] = scaled.clip(lower=lo, upper=hi)
    if not rel:
        raise ValueError("no operation is present in enough binaries to aggregate.")
    rel = pd.DataFrame(rel, index=counts.index)
    return pd.DataFrame({
        "score": rel.median(axis=1),
        "q25": rel.quantile(0.25, axis=1),
        "q75": rel.quantile(0.75, axis=1),
        "ops": rel.notna().sum(axis=1),
    })


# --- Drawing -----------------------------------------------------------------
def _fmt_bytes(n, _pos=None):
    # Decimal units, so the log axis' decade ticks read 100 kB / 1 MB / 10 MB.
    for unit, scale in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if n >= scale:
            return f"{n / scale:g} {unit}"
    return f"{n:g} B"


def _fmt_count(v, _pos=None):
    if v >= 1e6:
        return f"{v / 1e6:g}M"
    if v >= 1e3:
        return f"{v / 1e3:g}k"
    return f"{v:g}"


def _arch_style(arch):
    return ARCH_STYLE.get(arch, OTHER_STYLE)


def _arch_order(archs):
    known = list(ARCH_STYLE)
    present = set(archs)
    return [a for a in known if a in present] + sorted(present - set(known))


def _log_range(values):
    """(lo_exp, hi_exp, floor_y) for a log axis: whole decades spanning the
    positive *values* and the y position of the "none" floor below them."""
    lo_exp, hi_exp = 0, 2
    if len(values):
        lo_exp = math.floor(math.log10(min(values)))
        hi_exp = max(math.ceil(math.log10(max(values))), lo_exp + 1)
    return lo_exp, hi_exp, 10 ** (lo_exp - 0.7)


def _style_axes(ax, xs, lo_exp, hi_exp, floor_y, *, floor_label="none",
                fmt=_fmt_count):
    ax.set_xscale("log")
    ax.set_yscale("log")
    # A corpus spanning under two decades would get a single decade tick on
    # the x axis; label the 1-2-5 steps there instead.
    span = math.log10(max(xs) / min(xs)) if xs else 0
    if span < 2:
        ax.xaxis.set_major_locator(LogLocator(base=10, subs=(1.0, 2.0, 5.0)))
    ax.xaxis.set_major_formatter(FuncFormatter(_fmt_bytes))
    ax.xaxis.set_minor_formatter(FuncFormatter(lambda v, p: ""))
    ax.set_ylim(floor_y * 10 ** -0.35, 10 ** (hi_exp + 0.25))
    ax.yaxis.set_major_locator(FixedLocator(
        [floor_y] + [10.0 ** e for e in range(lo_exp, hi_exp + 1)]))
    ax.yaxis.set_major_formatter(FuncFormatter(
        lambda v, p: floor_label if v <= floor_y * 1.01 else fmt(v)))
    ax.yaxis.set_minor_locator(NullLocator())
    ax.axhline(floor_y, color=MUTED, lw=1, ls="--", zorder=1)
    ax.grid(axis="y", color=GRID, lw=0.8, zorder=0)
    ax.set_axisbelow(True)
    ax.tick_params(axis="both", length=0, labelcolor=MUTED, labelsize=8.5)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.set_xlabel("binary size on disk", color=MUTED, fontsize=9)


def _scatter(ax, xs, ys, archs, floor_y, *, size=46):
    """Points coloured/shaped by architecture; a zero value becomes a hollow
    marker on the floor line. Returns the legend handles, in ISA order."""
    handles = []
    for arch in _arch_order(archs):
        color, marker = _arch_style(arch)
        sel = [i for i, a in enumerate(archs) if a == arch]
        present = [i for i in sel if ys[i] > 0]
        absent = [i for i in sel if ys[i] <= 0]
        if present:
            ax.scatter([xs[i] for i in present], [ys[i] for i in present],
                       s=size, marker=marker, color=color, edgecolors="white",
                       linewidths=1.2, zorder=4)
        if absent:
            ax.scatter([xs[i] for i in absent], [floor_y] * len(absent),
                       s=size, marker=marker, facecolors="white",
                       edgecolors=color, linewidths=1.4, zorder=3)
        handles.append(Line2D([], [], ls="", marker=marker, color=color, ms=7,
                              mec="white", mew=1, label=f"{arch} ({len(sel)})"))
    return handles


def _trend(ax, xs, ys, *, label):
    """Theil–Sen power law through the positive points, over the data's x
    span. Returns a legend handle (None without enough points)."""
    pos = [(x, y) for x, y in zip(xs, ys) if x > 0 and y > 0]
    if len(pos) < MIN_FIT_POINTS:
        return None
    fit = theil_sen(np.log10([p[0] for p in pos]), np.log10([p[1] for p in pos]))
    if fit is None:
        return None
    slope, intercept = fit
    lo, hi = min(p[0] for p in pos), max(p[0] for p in pos)
    grid = np.logspace(math.log10(lo), math.log10(hi), 50)
    ax.plot(grid, 10 ** (intercept + slope * np.log10(grid)), color=INK, lw=1.6,
            alpha=0.85, zorder=2, solid_capstyle="round")
    return Line2D([], [], color=INK, lw=1.6, label=f"{label} ∝ size^{slope:.2f}")


def _legend(fig, handles):
    """Legend in a row under the axes, so it never covers a point."""
    fig.legend(handles=handles, loc="lower center", ncol=min(len(handles), 4),
               frameon=False, fontsize=8.5, labelcolor=INK, handletextpad=0.5,
               columnspacing=1.4, bbox_to_anchor=(0.5, -0.01))
    fig.tight_layout(rect=(0, 0.1 if len(handles) > 4 else 0.06, 1, 1))


def _subset(counts, arch, sizes):
    """Rows with a known size, as parallel lists (names, sizes, archs)."""
    names = [n for n in counts.index if n in sizes and sizes[n] > 0]
    return names, [float(sizes[n]) for n in names], [arch[n] for n in names]


def make_op_chart(counts, arch, sizes, op, *, title=None):
    """Gadgets of *op* vs. binary size, one point per binary."""
    if op not in counts.columns:
        raise KeyError(op)
    names, xs, archs = _subset(counts, arch, sizes)
    if not names:
        raise ValueError("no binary sizes known for these results "
                         "(no library_bytes in run-meta.yaml; try --binaries-dir).")
    ys = [float(counts.at[n, op]) for n in names]
    lo_exp, hi_exp, floor_y = _log_range([y for y in ys if y > 0])

    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    fig.patch.set_facecolor("white")
    _style_axes(ax, xs, lo_exp, hi_exp, floor_y)
    handles = _scatter(ax, xs, ys, archs, floor_y)
    trend = _trend(ax, xs, ys, label=f"{op} gadgets")
    if trend is not None:
        handles.append(trend)
    ax.set_ylabel(f"{op} gadgets found", color=MUTED, fontsize=9)
    absent = sum(1 for y in ys if y <= 0)
    sub = f"{len(names)} binaries" + (f" · {absent} without {op}" if absent else "")
    ax.set_title(title or f"{op}: gadgets vs. binary size", loc="left",
                 fontsize=12, fontweight="bold", color=INK, pad=18)
    ax.text(0, 1.02, sub, transform=ax.transAxes, fontsize=8.5, color=MUTED)
    _legend(fig, handles)
    return fig


def make_aggregate_chart(counts, arch, sizes, *, title=None):
    """Relative gadget abundance (median over operations, each scaled by its
    own median and winsorized) vs. binary size, with the interquartile range
    across operations as a thin bar behind every point."""
    names, xs, archs = _subset(counts, arch, sizes)
    if not names:
        raise ValueError("no binary sizes known for these results "
                         "(no library_bytes in run-meta.yaml; try --binaries-dir).")
    agg = relative_abundance(counts.loc[names])
    ys = list(agg["score"])
    q25, q75 = list(agg["q25"]), list(agg["q75"])
    lo_exp, hi_exp, floor_y = _log_range(
        [v for v in ys + q25 + q75 if v > 0])

    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    fig.patch.set_facecolor("white")
    _style_axes(ax, xs, lo_exp, hi_exp, floor_y, fmt=lambda v, p=None: f"{v:g}×")
    ax.axhline(1.0, color=AXIS, lw=1.2, zorder=1)
    for x, lo, hi in zip(xs, q25, q75):
        lo, hi = max(lo, floor_y), max(hi, floor_y)
        if hi > lo:
            ax.plot([x, x], [lo, hi], color=MUTED, lw=0.9, alpha=0.22, zorder=2,
                    solid_capstyle="round")
    handles = _scatter(ax, xs, ys, archs, floor_y)
    trend = _trend(ax, xs, ys, label="abundance")
    if trend is not None:
        handles.append(trend)
    handles.append(Line2D([], [], color=AXIS, lw=1.2, label="typical binary (1×)"))
    handles.append(Line2D([], [], color=MUTED, lw=1, alpha=0.5,
                          label="interquartile range across operations"))
    ax.set_ylabel("relative gadget abundance (median over operations)",
                  color=MUTED, fontsize=9)
    n_ops = int(agg["ops"].max())
    sub = (f"{len(names)} binaries · {n_ops} of {counts.shape[1]} operations · "
           f"each operation scaled by its median, clipped to its "
           f"{int(WINSOR[0] * 100)}–{int(WINSOR[1] * 100)}th percentile")
    ax.set_title(title or "All operations: relative abundance vs. binary size",
                 loc="left", fontsize=12, fontweight="bold", color=INK, pad=18)
    ax.text(0, 1.02, sub, transform=ax.transAxes, fontsize=8.5, color=MUTED)
    _legend(fig, handles)
    return fig


def figures(counts, arch, sizes, ops=None):
    """Yield (suffix, title, figure): the aggregate curve first, then one
    figure per operation (all of them, or just *ops*)."""
    try:
        yield "size_aggregate", "All operations", make_aggregate_chart(counts, arch, sizes)
    except ValueError as exc:
        print(f"  [WARN] aggregate chart skipped: {exc}", file=sys.stderr)
    for op in (ops or list(counts.columns)):
        try:
            yield f"size_{op}", op, make_op_chart(counts, arch, sizes, op)
        except ValueError as exc:
            print(f"  [WARN] {op} chart skipped: {exc}", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Render binary-size vs. gadget-count curves from a "
                    "run-experiments.py count-matrix TSV. Live preview by "
                    "default; --pdf/-o to save one file per figure.")
    ap.add_argument("tsv", help="result TSV (searched in --results-dir if not "
                                 "found as given)")
    ap.add_argument("--op", action="append", metavar="OP",
                    help="only this operation's figure (repeatable; the "
                         "aggregate is always drawn)")
    ap.add_argument("--no-aggregate", action="store_true",
                    help="skip the all-operations aggregate figure")
    ap.add_argument("--binaries-dir", metavar="DIR",
                    help="corpus folder to take binary sizes from when the "
                         "run-meta.yaml beside the TSV has no library_bytes")
    ap.add_argument("--write-sizes", action="store_true",
                    help="record the sizes found (run-meta + --binaries-dir) as "
                         "library_bytes in the run-meta.yaml beside the TSV, "
                         "then exit")
    ap.add_argument("--pdf", action="store_true",
                    help=f"save PDFs to {DEFAULT_RESULTS_DIR}/<name>_size_*.pdf "
                         "instead of previewing")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="save to FILE with _size_<op> appended to its name "
                         "(format from extension: .pdf/.png/.svg)")
    ap.add_argument("--show", action="store_true",
                    help="also open the live preview when saving")
    ap.add_argument("--backend", metavar="NAME",
                    help="force a matplotlib GUI backend (e.g. QtAgg, GTK4Agg, "
                         "TkAgg)")
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
        counts, arch = load_counts(src)
    except Exception as exc:
        print(f"ERROR: could not read {src!r}: {exc}", file=sys.stderr)
        return 1

    sizes = load_sizes(src, args.binaries_dir)
    missing = [n for n in counts.index if n not in sizes]
    if args.write_sizes:
        n = write_sizes(src, sizes, list(counts.index))
        print(f"Wrote {n} library sizes to {_meta_path(src)}"
              + (f" ({len(missing)} unknown: {', '.join(missing[:5])}"
                 + (", …" if len(missing) > 5 else "") + ")" if missing else ""))
        return 0 if n else 1
    if missing:
        print(f"  [WARN] binary sizes unknown for {len(missing)} of "
              f"{len(counts)} libraries (no library_bytes in run-meta.yaml; "
              "pass --binaries-dir): they are left out.", file=sys.stderr)
    unknown_ops = [op for op in (args.op or []) if op not in counts.columns]
    if unknown_ops:
        print(f"ERROR: no such operation {', '.join(unknown_ops)} "
              f"(have: {', '.join(counts.columns)})", file=sys.stderr)
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

    for suffix, _title, fig in figures(counts, arch, sizes, args.op):
        if args.no_aggregate and suffix == "size_aggregate":
            plt.close(fig)
            continue
        if saving:
            base, ext = os.path.splitext(out)
            path = f"{base}_{suffix}{ext}"
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            fig.savefig(path, dpi=args.dpi, facecolor="white",
                        bbox_inches="tight", pad_inches=0.1)
            print(f"Wrote {path}")

    if previewing:
        print(f"Opening live preview [{backend}] — close the windows to exit.")
        plt.show()
    return 0


if __name__ == "__main__":
    sys.exit(main())

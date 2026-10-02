#!/usr/bin/env python3
"""
Per-architecture line charts for compare-tools.py's long-format results.

Reads `results_compare.tsv` (one row per tool × binary × chain) and renders one
figure per architecture, with one panel per binary:

  * x axis: that architecture's ROP chains, ordered by how many ROPLang
    instructions the reference chain (`ropchains/rop3/<chain>.txt`) has;
  * y axis (log): total time to find the chain, `extract_seconds + seconds`
    (ropper's `--chain` is atomic, so its `seconds` already includes loading
    and its empty `extract_seconds` counts as 0 -- the sum is what makes the
    tools comparable);
  * one colour per tool, square markers joined by lines;
  * a dashed "∞" line at the top for everything that did not produce a chain
    (not-found, timeout, load-timeout, error: hollow square; no recipe for
    that tool/chain, i.e. `unsupported`: ×).

Same output conventions as utils/heatmap.py: live preview by default, --pdf or
-o FILE to save. One file is written per architecture, named
`<name>_<arch>.<ext>`.

    python utils/compare_plot.py results/compare_ropchains/results_compare.tsv
    python utils/compare_plot.py results_compare.tsv --pdf          # -> heatmap-results/
    python utils/compare_plot.py results_compare.tsv -o cmp.png --arch x86_64
"""
import os
import re
import sys
import math
import argparse

import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FixedLocator, FuncFormatter, NullLocator

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from heatmap import (  # noqa: E402
    ARCH_CANON, DEFAULT_RESULTS_DIR, _pretty_arch, _resolve_input,
    activate_gui_backend,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ROPCHAINS_DIR = os.path.join(REPO_ROOT, "ropchains", "rop3")
COMPARE_COLS = {"tool", "library", "arch", "chain", "found", "seconds", "status"}

# Fixed tool -> colour, so a tool keeps its colour on every architecture and
# whether or not the others are present in a given run. Order is also the
# legend/dodge order.
TOOL_COLORS = {
    "rop3":     "#2a78d6",
    "ropper":   "#eb6834",
    "angrop":   "#1baf7a",
    "ropium":   "#eda100",
    "pwntools": "#e87ba4",
}
OTHER_TOOL_COLOR = "#898781"

INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e1e0d9"
TIME_FLOOR = 1e-2       # seconds; log-axis floor for near-instant searches
DODGE = 0.055           # x offset between tools, so stacked markers stay visible

# ROPLang line shapes, as in rop3/rop3/ropchain.py (COMMENT / free()). Restated
# here so the site build needs neither the submodule nor capstone.
_COMMENT = re.compile(r"^(?:\s*;.*)?$")
_FREE = re.compile(r"^\s*free\s*\(")
_ARCH_TOKENS = {tok for toks, _ in ARCH_CANON for tok in toks}


def count_instructions(path):
    """Number of ROPLang instructions in a chain file: every non-blank,
    non-comment line except `free(NAME)`, which only releases a generic
    register slot and yields no gadget."""
    with open(path, encoding="utf-8") as f:
        return sum(1 for line in f
                   if not _COMMENT.match(line.rstrip("\n")) and not _FREE.match(line))


def _goal(chain):
    """Chain name without its trailing architecture token."""
    head, _, tail = str(chain).rpartition("_")
    return head if head and tail.lower() in _ARCH_TOKENS else str(chain)


def load_compare(tsv, ropchains_dir=DEFAULT_ROPCHAINS_DIR):
    """Read a compare-tools TSV and add the plotting columns: `ok` (a chain was
    found), `total` (extract + search seconds, floored) and `n_instr` (ROPLang
    instruction count; NaN when the reference chain file is missing)."""
    df = pd.read_csv(tsv, sep="\t", dtype=str, keep_default_na=False)
    missing = COMPARE_COLS - set(df.columns)
    if missing:
        raise ValueError(f"{tsv!r}: not a compare-tools TSV "
                         f"(missing {', '.join(sorted(missing))}).")
    df = df.drop_duplicates(["tool", "library", "chain"])

    df["ok"] = (df["found"].str.strip().str.lower().isin(("true", "1", "yes"))
                & (df["status"] == "found"))
    seconds = pd.to_numeric(df["seconds"], errors="coerce")
    extract = pd.to_numeric(df.get("extract_seconds"), errors="coerce")
    df["total"] = (seconds + extract.fillna(0)).clip(lower=TIME_FLOOR)

    counts = {}
    for chain in df["chain"].unique():
        path = os.path.join(ropchains_dir, f"{chain}.txt")
        counts[chain] = count_instructions(path) if os.path.isfile(path) else float("nan")
    df["n_instr"] = df["chain"].map(counts)
    return df


def arch_order(df):
    """Architectures present in *df*, in canonical ISA order."""
    return sorted(df["arch"].unique(), key=lambda a: (_pretty_arch(a)[0], a))


def make_compare_chart(df_arch, *, title=None):
    """One figure for one architecture's rows: a panel per binary, chains on x
    (ordered by instruction count), total seconds on a shared log y."""
    chains = (df_arch[["chain", "n_instr"]].drop_duplicates("chain")
              .sort_values(["n_instr", "chain"], na_position="last"))
    chain_ids = list(chains["chain"])
    xlabels = [f"{_goal(c)}\n({int(n)} instr.)" if pd.notna(n) else _goal(c)
               for c, n in zip(chains["chain"], chains["n_instr"])]
    libs = sorted(df_arch["library"].unique())

    # A tool with no recipe for any of this architecture's chains has nothing
    # to show here; leave it out rather than draw a dead series.
    present = set(df_arch.loc[df_arch["status"] != "unsupported", "tool"])
    tools = ([t for t in TOOL_COLORS if t in present]
             + sorted(present - set(TOOL_COLORS)))

    # Shared y range: whole decades around the found times, ∞ line above them.
    found = df_arch.loc[df_arch["ok"], "total"]
    lo_exp, hi_exp = -1, 2
    if not found.empty:
        lo_exp = math.floor(math.log10(found.min()))
        hi_exp = max(math.ceil(math.log10(found.max())), lo_exp + 1)
    inf_y = 10 ** (hi_exp + 0.7)

    fig, axes = plt.subplots(1, len(libs), sharey=True, squeeze=False,
                             figsize=(3.4 * len(libs) + 1.4, 4.6))
    fig.patch.set_facecolor("white")
    for ax, lib in zip(axes[0], libs):
        sub = df_arch[df_arch["library"] == lib].set_index(["tool", "chain"])
        ax.axhline(inf_y, color=MUTED, lw=1, ls="--", zorder=1)
        for i, tool in enumerate(tools):
            color = TOOL_COLORS.get(tool, OTHER_TOOL_COLOR)
            dx = (i - (len(tools) - 1) / 2) * DODGE
            xs, ys, oks, stats = [], [], [], []
            for x, chain in enumerate(chain_ids):
                if (tool, chain) not in sub.index:
                    continue
                row = sub.loc[(tool, chain)]
                xs.append(x + dx)
                oks.append(bool(row["ok"]))
                ys.append(row["total"] if row["ok"] else inf_y)
                stats.append(row["status"])
            if not xs:
                continue
            # Dotted through every point (so a run up to ∞ reads as "lost
            # here"), solid only between two consecutive found chains.
            ax.plot(xs, ys, color=color, lw=1.2, ls=":", alpha=0.7, zorder=2)
            solid = [y if ok else float("nan") for y, ok in zip(ys, oks)]
            ax.plot(xs, solid, color=color, lw=2, zorder=3)
            for x, y, ok, status in zip(xs, ys, oks, stats):
                if ok:
                    ax.plot(x, y, marker="s", ms=8, color=color, mec="white",
                            mew=1.2, ls="none", zorder=4)
                elif status == "unsupported":
                    ax.plot(x, y, marker="x", ms=7, color=color, mew=1.8,
                            ls="none", zorder=4, clip_on=False)
                else:
                    ax.plot(x, y, marker="s", ms=8, mfc="white", mec=color,
                            mew=1.8, ls="none", zorder=4, clip_on=False)

        ax.set_title(lib, fontsize=9.5, color=INK, pad=8)
        ax.set_xticks(range(len(chain_ids)))
        ax.set_xticklabels(xlabels, fontsize=8.5, color=MUTED)
        ax.set_xlim(-0.5, len(chain_ids) - 0.5)
        ax.set_yscale("log")
        ax.set_ylim(10 ** lo_exp, inf_y * 10 ** 0.25)
        ax.yaxis.set_major_locator(FixedLocator(
            [10.0 ** e for e in range(lo_exp, hi_exp + 1)] + [inf_y]))
        ax.yaxis.set_major_formatter(FuncFormatter(
            lambda v, _pos: "∞" if v >= inf_y * 0.99 else f"{v:g}"))
        ax.yaxis.set_minor_locator(NullLocator())
        ax.grid(axis="y", color=GRID, lw=0.8, zorder=0)
        ax.set_axisbelow(True)
        ax.tick_params(axis="both", length=0, labelcolor=MUTED, labelsize=8.5)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color("#c3c2b7")

    axes[0][0].set_ylabel("total time: load + search (s)", color=MUTED, fontsize=9)
    fig.supxlabel("ROP chain, by number of ROPLang instructions",
                  color=MUTED, fontsize=9, y=0.105)
    if title:
        fig.suptitle(title, fontsize=13, fontweight="bold", color=INK)

    handles = [Line2D([], [], color=TOOL_COLORS.get(t, OTHER_TOOL_COLOR), lw=2,
                      marker="s", ms=7, mec="white", mew=1, label=t) for t in tools]
    shown = df_arch[df_arch["tool"].isin(tools)]
    if (~shown["ok"] & (shown["status"] != "unsupported")).any():
        handles.append(Line2D([], [], ls="none", marker="s", ms=7, mfc="white",
                              mec=MUTED, mew=1.6,
                              label="no chain (not found / timeout / error)"))
    if (shown["status"] == "unsupported").any():
        handles.append(Line2D([], [], ls="none", marker="x", ms=7, color=MUTED,
                              mew=1.6, label="no recipe for this tool"))
    fig.legend(handles=handles, loc="lower center",
               ncol=len(handles) if len(libs) >= 3 else math.ceil(len(handles) / 2),
               frameon=False, fontsize=8.5, labelcolor=INK,
               bbox_to_anchor=(0.5, -0.03), columnspacing=1.4, handletextpad=0.5)
    fig.tight_layout(rect=(0, 0.14, 1, 1))
    return fig


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Render per-architecture tool-comparison line charts from "
                    "a compare-tools.py result TSV. Live preview by default; "
                    "--pdf/-o to save one file per architecture.")
    ap.add_argument("tsv", help="results_compare.tsv (searched in --results-dir "
                                 "if not found as given)")
    ap.add_argument("--ropchains-dir", default=DEFAULT_ROPCHAINS_DIR,
                    help="directory of reference ROPLang chains, used to count "
                         "instructions (default: ropchains/rop3)")
    ap.add_argument("--arch", action="append", metavar="ARCH",
                    help="only this architecture, as in the TSV's arch column "
                         "(repeatable; default: all)")
    ap.add_argument("--pdf", action="store_true",
                    help=f"save PDFs to {DEFAULT_RESULTS_DIR}/<name>_<arch>.pdf "
                         "instead of previewing")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="save to FILE with _<arch> appended to its name "
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
        df = load_compare(src, args.ropchains_dir)
    except Exception as exc:
        print(f"ERROR: could not read {src!r}: {exc}", file=sys.stderr)
        return 1

    archs = arch_order(df)
    if args.arch:
        unknown = [a for a in args.arch if a not in archs]
        if unknown:
            print(f"ERROR: no rows for arch {', '.join(unknown)} "
                  f"(have: {', '.join(archs)})", file=sys.stderr)
            return 1
        archs = [a for a in archs if a in args.arch]
    if df["n_instr"].isna().any():
        print(f"  [WARN] some chains have no reference file under "
              f"{args.ropchains_dir!r}; they are placed last on the x axis.",
              file=sys.stderr)

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

    for arch in archs:
        fig = make_compare_chart(df[df["arch"] == arch], title=_pretty_arch(arch)[1])
        if saving:
            base, ext = os.path.splitext(out)
            path = f"{base}_{arch}{ext}"
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

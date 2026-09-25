#!/usr/bin/env python3
"""
Build a static site out of results/<experiment>/*.tsv for GitHub Pages.

For every result TSV under --results-dir, renders a heatmap PNG (reusing
load_matrix()/make_heatmap() from utils/heatmap.py) and copies the raw TSV,
then emits a single index.html grouping them by experiment (the results/
subdirectory name). The page opens with the benchmark machine (machine.yaml),
and an experiment that recorded its own provenance (results/<experiment>/
run-meta.yaml, written by run-experiments.py) gets a note under its heading --
including its own machine block when it ran somewhere other than machine.yaml. A TSV that doesn't fit the heatmap model (e.g. ropchains
output, which is boolean-valued) still gets a card with a download link, just
without a preview image.

    python utils/build_site.py --results-dir results --out _site
"""
import argparse
import csv
import html
import os
import re
import shutil
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless: never touch a GUI backend
import matplotlib.pyplot as plt

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from heatmap import load_matrix, make_heatmap  # noqa: E402
import machine_specs  # noqa: E402

PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>rop3-eval results</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 1100px;
         padding: 0 1rem; line-height: 1.5; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .sub {{ color: #777; margin-top: 0; }}
  section {{ margin: 2.5rem 0; }}
  section h2 {{ border-bottom: 1px solid #8884; padding-bottom: 0.3rem; }}
  .card {{ border: 1px solid #8884; border-radius: 8px; padding: 1rem;
          margin: 1rem 0; }}
  .card h3 {{ margin-top: 0; font-family: monospace; }}
  .card img {{ max-width: 100%; height: auto; border-radius: 4px; }}
  .no-preview {{ color: #999; font-style: italic; }}
  a.download {{ display: inline-block; margin-top: 0.5rem; }}
  .tablewrap {{ overflow-x: auto; max-height: 32rem; overflow-y: auto;
                border: 1px solid #8883; border-radius: 6px; }}
  table.results {{ border-collapse: collapse; width: 100%; font-size: 0.9rem; }}
  table.results th, table.results td {{ padding: 0.35rem 0.6rem;
                                        border-bottom: 1px solid #8882;
                                        text-align: left; white-space: nowrap; }}
  table.results thead th {{ position: sticky; top: 0; background: #8881;
                            backdrop-filter: blur(4px); font-weight: 600; }}
  table.results td.num {{ text-align: right;
                          font-variant-numeric: tabular-nums;
                          font-family: ui-monospace, monospace; }}
  table.results td.ok {{ color: #1a7f37; font-weight: 600; }}
  table.results td.no {{ color: #b0812f; }}
  table.results .badge {{ font-size: 0.78rem; color: #888;
                          font-family: ui-monospace, monospace; }}
  table.results tbody tr:hover td {{ background: #8881; }}
  table.results td.toggle {{ width: 1.4rem; text-align: center;
                             padding: 0 0.2rem; }}
  button.chain-toggle {{ font: inherit; cursor: pointer; border: none;
                         background: none; color: #888; line-height: 1;
                         padding: 0.1rem 0.3rem; }}
  button.chain-toggle:hover {{ color: inherit; }}
  tr.chain-row td {{ padding: 0; white-space: normal; }}
  tr.chain-row[hidden] {{ display: none; }}
  pre.chain {{ margin: 0; padding: 0.6rem 0.9rem; overflow-x: auto;
               font-family: ui-monospace, monospace; font-size: 0.8rem;
               background: #8881; }}
  pre.chain .ansi-90 {{ color: #888; }}
  pre.chain .ansi-93 {{ color: #b58900; }}
  section.machine {{ border: 1px solid #8884; border-radius: 8px;
                     padding: 1rem 1.25rem; background: #8881; margin: 1.5rem 0; }}
  section.machine h2 {{ margin: 0 0 0.4rem; border: none; padding: 0;
                        font-size: 0.8rem; text-transform: uppercase;
                        letter-spacing: 0.08em; color: #888; }}
  .machine-label {{ margin: 0 0 0.9rem; }}
  .muted {{ color: #888; font-weight: 400; }}
  dl.specs {{ display: grid; margin: 0;
              grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
              gap: 0.1rem 1.5rem; }}
  dl.specs dt {{ font-size: 0.72rem; text-transform: uppercase;
                 letter-spacing: 0.05em; color: #888; }}
  dl.specs dd {{ margin: 0 0 0.6rem; font-variant-numeric: tabular-nums; }}
  .machine-notes {{ color: #888; font-size: 0.9rem; white-space: pre-line;
                    margin: 0.9rem 0 0; }}
  .provenance {{ color: #888; font-size: 0.82rem; margin: 0.4rem 0 1rem;
                 font-family: ui-monospace, monospace; }}
</style>
</head>
<body>
<h1>rop3-eval results</h1>
<p class="sub">ROP / JOP / ROPBLOCK gadget-search results across the analyzed
binary corpus.</p>
{machine}
{sections}
{script}
</body>
</html>
"""

# Collapsible ROP-chain rows: one delegated click handler toggles the detail row
# that follows each toggle button. Injected as a format *value*, so — unlike the
# CSS above — its braces are NOT doubled.
PAGE_SCRIPT = """<script>
document.addEventListener('click', function (e) {
  var btn = e.target.closest && e.target.closest('.chain-toggle');
  if (!btn) return;
  var detail = btn.closest('tr') && btn.closest('tr').nextElementSibling;
  if (!detail || !detail.classList.contains('chain-row')) return;
  var opening = detail.hasAttribute('hidden');
  if (opening) detail.removeAttribute('hidden');
  else detail.setAttribute('hidden', '');
  btn.setAttribute('aria-expanded', opening ? 'true' : 'false');
  btn.textContent = opening ? '\\u25bc' : '\\u25b6';
});
</script>"""

SECTION_TEMPLATE = """<section>
<h2>{name}</h2>
{provenance}
{cards}
</section>
"""

CARD_TEMPLATE = """<div class="card">
<h3>{stem}</h3>
{body}
<a class="download" href="{tsv_href}">Download TSV</a>
</div>
"""


def experiment_title(exp_name, experiments_dir):
    """Human-readable section heading for an experiment.

    Reads the `name:` field from experiments/<exp_name>.yaml (the config that
    produced results/<exp_name>/, per experiments/run_all.py's convention).
    Falls back to a prettified version of the directory name if the config is
    missing or has no `name:` field.
    """
    config_path = Path(experiments_dir) / f"{exp_name}.yaml"
    if config_path.is_file():
        try:
            with open(config_path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            name = cfg.get("name")
            if name:
                return str(name)
        except Exception as exc:
            print(f"  [WARN] could not read {config_path}: {exc}", file=sys.stderr)
    return exp_name.replace("_", " ").replace("-", " ").strip().title()


def experiment_provenance(exp_dir, site_machine):
    """Provenance note for one experiment, from results/<exp>/run-meta.yaml.

    run-experiments.py writes that file beside the TSV it produced. Timings are
    only comparable within one machine, so an experiment whose machine differs
    from the site-wide machine.yaml gets its own full spec block rather than a
    one-liner.
    """
    meta_path = Path(exp_dir) / "run-meta.yaml"
    if not meta_path.is_file():
        return ""
    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = yaml.safe_load(f) or {}
    except Exception as exc:
        print(f"  [WARN] could not read {meta_path}: {exc}", file=sys.stderr)
        return ""
    if not isinstance(meta, dict):
        return ""

    bits = []
    generated = str(meta.get("generated") or "")[:10]
    if generated:
        bits.append(f"run {generated}")
    commit = meta.get("rop3_commit")
    if commit:
        bits.append(f"rop3 {str(commit)[:8]}")
    if meta.get("config_hash"):
        bits.append(f"config {meta['config_hash']}")
    elapsed = meta.get("elapsed_seconds")
    if elapsed is not None:
        bits.append(f"{float(elapsed):.0f}s")
    reused, libraries = meta.get("reused_from_cache"), meta.get("libraries")
    if reused:
        bits.append(f"{reused}/{libraries} libraries reused from cache")

    machine = meta.get("machine") or {}
    label = machine.get("label") or machine.get("id")
    differs = bool(machine) and machine.get("id") != (site_machine or {}).get("id")
    if label and not differs:
        bits.append(f"on {label}")

    note = ('<p class="provenance">' + " · ".join(html.escape(b) for b in bits) + "</p>"
            if bits else "")
    if differs:
        note += machine_specs.render_html(machine, heading="Machine for this experiment")
    return note


ROPCHAIN_COLS = {"library", "chain", "found", "seconds"}
CHAIN_COL = "chain_text"        # long, multi-line; shown collapsibly, not inline
_CHAIN_UNESCAPE = {"\\\\": "\\", "\\n": "\n", "\\t": "\t", "\\r": "\r"}


def _fmt_seconds(value):
    """Render a seconds cell: 2-dp float, or '—' for blank/non-numeric (e.g. a
    'fatal' row where the search never ran)."""
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "—"


def _decode_chain(value):
    """Reverse compare-tools' _tsv_escape (backslash/tab/CR/LF) in one
    left-to-right pass, so an escaped backslash never re-triggers a decode."""
    return re.sub(r"\\[\\ntr]", lambda m: _CHAIN_UNESCAPE[m.group(0)], value or "")


# rop3 colourises its gadget dump with ANSI SGR codes (grey for the return
# instruction, yellow for highlights); those raw ESC bytes land verbatim in
# chain_text and a browser renders them as `[90m…[0m` noise. Map the few codes
# rop3 emits to <span> classes so the chain reads cleanly and keeps its colour.
_SGR_RE = re.compile("\033\\[([0-9;]*)m")
_SGR_CLASS = {"90": "ansi-90", "93": "ansi-93"}


def _ansi_to_html(text):
    """HTML-escape *text* and turn its ANSI SGR sequences into <span> tags: a
    known colour code opens a span, a reset (`0`, or an empty code) closes every
    open span, and unrecognised codes are dropped. Any span left open at the end
    is closed, so the emitted markup is always balanced."""
    out = []
    open_spans = 0
    pos = 0
    for m in _SGR_RE.finditer(text):
        out.append(html.escape(text[pos:m.start()]))
        pos = m.end()
        codes = [c for c in m.group(1).split(";") if c]
        if not codes or "0" in codes:          # reset: close everything open
            out.append("</span>" * open_spans)
            open_spans = 0
            continue
        for code in codes:
            cls = _SGR_CLASS.get(code)
            if cls:
                out.append(f'<span class="{cls}">')
                open_spans += 1
    out.append(html.escape(text[pos:]))
    out.append("</span>" * open_spans)
    return "".join(out)


def _ropchain_table_html(tsv):
    """HTML <table> for a long-format ropchain-benchmark TSV (one row per
    binary×chain pair). Returns None if the TSV isn't that shape, so the caller
    can fall through to the heatmap path. A `chain_text` column (compare-tools)
    is not rendered as a cell; instead each row with a chain gets a toggle that
    reveals the chain in a collapsed detail row (hidden by default)."""
    with open(tsv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        cols = reader.fieldnames or []
        if not ROPCHAIN_COLS.issubset(cols):
            return None
        rows = list(reader)

    has_chain = CHAIN_COL in cols
    display_cols = [c for c in cols if c != CHAIN_COL]
    span = len(display_cols) + 1        # +1 for the leading toggle column
    # Numeric columns are right-aligned; found renders as a ✓/✗ glyph.
    num_cols = {"seconds", "extract_seconds"}
    head = ('<th class="toggle"></th>'
            + "".join(f"<th>{html.escape(c)}</th>" for c in display_cols))
    body_rows = []
    for row in rows:
        chain = _decode_chain(row.get(CHAIN_COL, "")) if has_chain else ""
        expandable = bool(chain.strip())
        if expandable:
            cells = ['<td class="toggle"><button type="button" '
                     'class="chain-toggle" aria-expanded="false" '
                     'aria-label="Toggle chain">▶</button></td>']
        else:
            cells = ['<td class="toggle"></td>']
        for c in display_cols:
            raw = row.get(c, "")
            if c == "found":
                yes = str(raw).strip().lower() in ("true", "1", "yes")
                cls = "ok" if yes else "no"
                cells.append(f'<td class="{cls}">{"✓" if yes else "✗"}</td>')
            elif c in num_cols:
                cells.append(f'<td class="num">{html.escape(_fmt_seconds(raw))}</td>')
            elif c == "status":
                cells.append(f'<td><span class="badge">{html.escape(str(raw))}</span></td>')
            else:
                cells.append(f"<td>{html.escape(str(raw))}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
        if expandable:
            body_rows.append(
                f'<tr class="chain-row" hidden><td colspan="{span}">'
                f'<pre class="chain">{_ansi_to_html(chain)}</pre></td></tr>')

    return (
        '<div class="tablewrap"><table class="results">'
        f"<thead><tr>{head}</tr></thead>"
        f'<tbody>{"".join(body_rows)}</tbody>'
        "</table></div>"
    )


def render_experiment(exp_dir, out_dir, exp_name):
    img_dir = out_dir / "img" / exp_name
    data_dir = out_dir / "data" / exp_name
    img_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    cards = []
    for tsv in sorted(exp_dir.glob("*.tsv")):
        stem = tsv.stem
        shutil.copy2(tsv, data_dir / tsv.name)
        tsv_href = f"data/{exp_name}/{tsv.name}"

        # Long-format ropchain-benchmark TSVs are string-valued and would coerce
        # to an all-zero heatmap, so detect and render them as a real table
        # first; only genuine count matrices fall through to make_heatmap().
        table_html = _ropchain_table_html(str(tsv))
        if table_html is not None:
            cards.append(CARD_TEMPLATE.format(
                stem=html.escape(stem), body=table_html, tsv_href=tsv_href))
            continue

        try:
            df = load_matrix(str(tsv))
            fig = make_heatmap(df, title=f"{exp_name} / {stem}")
            # make_heatmap() sets the figure/axes background fully transparent
            # (for the CLI's --pdf/interactive use, which may be composited
            # onto a dark slide). Here the PNG is embedded directly in an HTML
            # page whose background can be dark (color-scheme: light dark),
            # and the annotation/tick-label text is unconditionally black —
            # transparent + black text would be unreadable in dark mode. Force
            # an opaque white backing so the chart is legible in either theme.
            fig.patch.set_alpha(1)
            fig.patch.set_facecolor("white")
            for ax in fig.axes:
                ax.patch.set_alpha(1)
                ax.patch.set_facecolor("white")
            png_path = img_dir / f"{stem}.png"
            fig.savefig(png_path, dpi=150, transparent=False, facecolor="white",
                        bbox_inches="tight", pad_inches=0.05)
            plt.close(fig)
            body = f'<img src="img/{exp_name}/{stem}.png" alt="{html.escape(stem)} heatmap">'
        except Exception as exc:
            print(f"  [WARN] could not render {tsv}: {exc}", file=sys.stderr)
            body = f'<p class="no-preview">No preview available ({html.escape(str(exc))}).</p>'

        cards.append(CARD_TEMPLATE.format(
            stem=html.escape(stem), body=body, tsv_href=tsv_href))

    return cards


def build(results_dir, out_dir, experiments_dir="experiments",
          machine_file=machine_specs.DEFAULT_MACHINE_FILE):
    results_dir = Path(results_dir)
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    site_machine = machine_specs.load(machine_file)
    if site_machine is None:
        print(f"[WARN] no machine specs at {machine_file}; the site will not say "
              "which machine produced these timings "
              "(generate one with `python utils/machine_specs.py --write`)",
              file=sys.stderr)

    exp_dirs = sorted(p for p in results_dir.iterdir() if p.is_dir())
    if not exp_dirs:
        print(f"[WARN] no experiment subdirectories found under {results_dir}",
              file=sys.stderr)

    sections = []
    for exp_dir in exp_dirs:
        exp_name = exp_dir.name
        cards = render_experiment(exp_dir, out_dir, exp_name)
        if not cards:
            continue
        title = experiment_title(exp_name, experiments_dir)
        sections.append(SECTION_TEMPLATE.format(
            name=html.escape(title),
            provenance=experiment_provenance(exp_dir, site_machine),
            cards="\n".join(cards)))

    index_path = out_dir / "index.html"
    index_path.write_text(PAGE_TEMPLATE.format(
        machine=machine_specs.render_html(site_machine),
        sections="\n".join(sections),
        script=PAGE_SCRIPT), encoding="utf-8")
    print(f"Wrote {index_path} ({len(sections)} experiment section(s))")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="results",
                     help="directory holding results/<experiment>/*.tsv (default: results)")
    ap.add_argument("--experiments-dir", default="experiments",
                     help="directory holding experiments/<experiment>.yaml configs, "
                          "used to look up each experiment's `name:` for its section "
                          "heading (default: experiments)")
    ap.add_argument("--machine-file", default=str(machine_specs.DEFAULT_MACHINE_FILE),
                     help="YAML describing the benchmark machine, rendered at the top "
                          "of the page (default: machine.yaml at the repo root)")
    ap.add_argument("--out", default="_site",
                     help="output directory for the built site (default: _site)")
    args = ap.parse_args(argv)
    build(args.results_dir, args.out, args.experiments_dir, args.machine_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())

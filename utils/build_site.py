#!/usr/bin/env python3
"""
Build a static site out of results/<experiment>/*.tsv for GitHub Pages.

For every result TSV under --results-dir, renders a heatmap PNG (reusing
load_matrix()/make_heatmap() from utils/heatmap.py) and copies the raw TSV,
then emits a single index.html grouping them by experiment (the results/
subdirectory name). A TSV that doesn't fit the heatmap model (e.g. ropchains
output, which is boolean-valued) still gets a card with a download link, just
without a preview image.

    python utils/build_site.py --results-dir results --out _site
"""
import argparse
import html
import os
import shutil
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless: never touch a GUI backend

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from heatmap import load_matrix, make_heatmap  # noqa: E402

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
</style>
</head>
<body>
<h1>rop3-eval results</h1>
<p class="sub">Gadget-search results for the <em>Evaluating the Execution
Capabilities of Attackers on Unix Systems using Return Oriented Programming</em>
experiment harness.</p>
{sections}
</body>
</html>
"""

SECTION_TEMPLATE = """<section>
<h2>{name}</h2>
{cards}
</section>
"""

CARD_TEMPLATE = """<div class="card">
<h3>{stem}</h3>
{body}
<a class="download" href="{tsv_href}">Download TSV</a>
</div>
"""


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

        try:
            df = load_matrix(str(tsv))
            fig = make_heatmap(df, title=f"{exp_name} / {stem}")
            png_path = img_dir / f"{stem}.png"
            fig.savefig(png_path, dpi=150, transparent=True,
                        bbox_inches="tight", pad_inches=0.05)
            import matplotlib.pyplot as plt
            plt.close(fig)
            body = f'<img src="img/{exp_name}/{stem}.png" alt="{html.escape(stem)} heatmap">'
        except Exception as exc:
            print(f"  [WARN] could not render {tsv}: {exc}", file=sys.stderr)
            body = f'<p class="no-preview">No preview available ({html.escape(str(exc))}).</p>'

        cards.append(CARD_TEMPLATE.format(
            stem=html.escape(stem), body=body, tsv_href=tsv_href))

    return cards


def build(results_dir, out_dir):
    results_dir = Path(results_dir)
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

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
        sections.append(SECTION_TEMPLATE.format(
            name=html.escape(exp_name), cards="\n".join(cards)))

    index_path = out_dir / "index.html"
    index_path.write_text(PAGE_TEMPLATE.format(sections="\n".join(sections)))
    print(f"Wrote {index_path} ({len(sections)} experiment section(s))")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="results",
                     help="directory holding results/<experiment>/*.tsv (default: results)")
    ap.add_argument("--out", default="_site",
                     help="output directory for the built site (default: _site)")
    args = ap.parse_args(argv)
    build(args.results_dir, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

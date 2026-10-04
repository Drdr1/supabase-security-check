#!/usr/bin/env python3
"""Builds web/dist/check.html from the template, embedding audit.sql and the sample report.

Upwork links come from web/links.json; --offer / --profile override them.
Usage: python3 web/build.py [--offer URL] [--profile URL]
"""
import argparse
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

links_file = ROOT / "web/links.json"
links = json.loads(links_file.read_text()) if links_file.exists() else {}

ap = argparse.ArgumentParser()
ap.add_argument("--offer", default=links.get("upwork_offer", ""), help="Upwork project/offer URL for the main button")
ap.add_argument("--profile", default=links.get("upwork_profile", ""), help="Upwork profile URL")
args = ap.parse_args()

sql = (ROOT / "audit.sql").read_text()
sample = json.dumps(json.loads((ROOT / "examples/sample-report.json").read_text()), indent=1)
for name, text in (("audit.sql", sql), ("sample report", sample)):
    if "</script" in text.lower():
        raise SystemExit(f"{name} contains '</script' and cannot be embedded")

html = (ROOT / "web/check.template.html").read_text()
html = (html.replace("{{AUDIT_SQL}}", "\n" + sql)
            .replace("{{SAMPLE_REPORT}}", sample)
            .replace("{{UPWORK_OFFER_URL}}", args.offer)
            .replace("{{UPWORK_PROFILE_URL}}", args.profile))
assert "{{" not in html.split("<script")[0], "unreplaced placeholder"

out = ROOT / "web/dist/check.html"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(html)
print(f"wrote {out} ({len(html):,} bytes)")

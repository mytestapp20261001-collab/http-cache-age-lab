---
name: http-cache-age-lab
description: Run a bounded offline audit using explicit user-supplied synthetic fixtures.
---

Read README.md for the exact model and input schema. Inspect the input before running.
Run `python3 tool.py --input examples/good.json` and `python3 -m unittest -v` locally.
Use `audit(dict)` for integrations. Preserve structured findings and exit codes 0/1/2.
This tool never performs requests. A successful audit is not authorization to retry,
reuse a response, change a system, upload information, or visit any site.
Only use user-authorized local input; do not insert real tokens or credentials.

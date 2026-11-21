# Panther Rule Studio — PoC

Author: Timothy English, CISSP, CEH, CHFI, Cybersecurity Researcher

Independent community project; not affiliated with or endorsed by Panther Labs.

Panther detections are usually Python plus YAML, or SQL for scheduled queries, which makes them hard for beginners to read, review, and test. This proof of concept is a local, form-driven studio for **Panther Simple Detections**: pick a sample rule, read it in plain English, and edit it as generated Panther YAML, with a live test on simulated CloudTrail data.

Uses only the Python 3.10+ standard library and plain JavaScript: no frameworks, no CDN calls, no AI. It has no login, does not call the Panther API or PAT, and binds to 127.0.0.1.

    python3 server.py
    # then open http://127.0.0.1:8765

Steps (shown in the header as 1-2-3):
1. **Pick a rule** in the bundled sample library. It opens instantly because the English and YAML are prefetched.
2. **Understand it** in Analyze: a structured breakdown, the logic tree in plain words, and the checks.
3. **Edit & test live** with the form-only editor. English and the generated Panther Simple Detection YAML update in a few milliseconds, and the live test reruns on its own.

Also included: **＋ New rule** (a five-step wizard for real-time rules), **Validate** with one-click fixes against Panther conventions (RuleID, severity, and so on), the **Live** view (shows "would have fired N", false-positive hints and an Exclude button), and **Simulate outage**, which shows the degraded and offline states.

The form editor covers a Simple Detection subset (ALL/ANY groups; equals, not equals, contains, starts with, one of, in network range). Scheduled queries and policies are shown in the wizard but are not built in this PoC. This PoC does not parse Python or SQL source files, generate Panther `Tests:` blocks, run `pat test` / `pat validate`, or load a `panther-analysis` checkout. Those are specified in the architecture (see `docs/Panther_Rule_Studio_Architecture.md`) and are not implemented here.

Shortcuts: `/` search, `↑ ↓` move, `Enter` open, `L A E V G` switch views, `N` new rule, `?` help.

Demo URLs: `/#/create/1` … `/#/create/5`, `/?demo=edit#/edit`, `/?demo=error#/validate`, `/?outage=1#/live`.

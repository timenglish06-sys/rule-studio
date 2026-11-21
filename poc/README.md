# Panther Rule Studio — PoC

Author: Timothy English, CISSP, CEH, CHFI, Cybersecurity Researcher

Uses only the Python 3.10+ standard library and plain JavaScript: no frameworks, no CDN calls, no AI. It runs on simulated data, has no login, and binds to 127.0.0.1.

    python3 server.py
    # then open http://127.0.0.1:8765

Steps (shown in the header as 1-2-3):
1. **Pick a rule** in the library. It opens instantly because the English and YAML are prefetched.
2. **Understand it** in Analyze: a structured breakdown, the logic tree in plain words, and the checks.
3. **Edit & test live** with the form-only editor. English and YAML update in a few milliseconds, and the live test reruns on its own.

Also included: **＋ New rule** (a five-step wizard), **Validate** with one-click fixes, the **Live** view (shows "would have fired N", false-positive hints and an Exclude button), and **Simulate outage**, which shows the degraded and offline states.

Shortcuts: `/` search, `↑ ↓` move, `Enter` open, `L A E V G` switch views, `N` new rule, `?` help.

Demo URLs: `/#/create/1` … `/#/create/5`, `/?demo=edit#/edit`, `/?demo=error#/validate`, `/?outage=1#/live`.

To use real data, replace `SimulatedSource` with an adapter that polls Panther's GraphQL `executeDataLakeQuery` and `dataLakeQuery` (spec §14).

# Rule Studio

Detection rules are hard to read, harder to review, and too easy to ship untested. A YAML file, a Python `rule()` function, or a scheduled SQL query can hide the logic that decides whether an analyst gets paged — and most of us are not full-time Python developers.

**Rule Studio** is a fast, form-driven detection rule studio that lets you write, read, and test rules in the browser, with live plain-English explanations. No LLM. Nothing leaves your machine.

## What it does

- **Parses YAML, Python, and SQL rules** into a structured model so you can inspect them without spelunking through code
- **Form-driven rule creation** — a guided wizard builds the rule; you don't have to start from a blank YAML file
- **Live validation** that flags problems as you edit, with one-click fixes in the PoC
- **Logic-tree explanations in plain English** that update as you change the form — what the rule catches, when it fires, and what happens next
- **Built-in tests and live analysis** on a simulated event stream: would-have-fired counts, matches, and false-positive hints
- **No LLM, and no data leaving your machine** — Python standard library and plain JavaScript, bound to `127.0.0.1`, running on simulated data

## See it

![Analyze a rule as a structured breakdown and logic tree](docs/screens/02-analyze-breakdown.png)

![Edit a rule and watch the English and YAML update live](docs/screens/08-edit-live-english-yaml.png)

## 60-second quickstart

You need Python 3.10 or later. No packages to install.

```bash
cd poc
python3 server.py
```

Then open http://127.0.0.1:8765

1. Pick a rule in the library — it opens instantly.
2. Read it in Analyze: the breakdown, the logic tree in plain words, and the checks.
3. Edit it in the form. English and YAML update in milliseconds, and the live test reruns on its own.

Demo URLs once the server is up: `/#/create/1` through `/#/create/5`, `/?demo=edit#/edit`, `/?demo=error#/validate`, `/?outage=1#/live`.

Shortcuts: `/` search, `↑ ↓` move, `Enter` open, `L A E V G` switch views, `N` new rule, `?` help.

## Who it's for

- **SOC analysts** who need to understand what a detection actually does before they trust the alert
- **Detection engineers** who want to draft and validate rules without bouncing between a text editor, a linter, and a console
- **Team leads and reviewers** who are signing off on rule changes and want a readable explanation, not just a diff

If you can fill out a form, you can work a rule in Rule Studio.

## Architecture in brief

The PoC is a local web app: a Python standard-library server and a dependency-free UI. Rules are parsed into an intermediate representation, rendered as a logic tree in plain English, validated statically, and evaluated against a simulated event stream pushed to the browser over SSE. User code is never executed. There is no cloud backend and no model.

The full design — parsers, the intermediate representation, the renderer, validation, live analysis, and the security model — is in the [architecture specification (v1.2)](docs/Panther_Rule_Studio_Architecture.md). A Word copy with embedded screenshots is in [`docs/Panther_Rule_Studio_Architecture.docx`](docs/Panther_Rule_Studio_Architecture.docx). The current spec still includes some SIEM-specific adapter notes; Rule Studio itself is vendor-neutral.

### Repository layout

```
poc/                 Proof-of-concept app (server, UI, and styles)
docs/                Architecture specification (Markdown and Word)
docs/screens/        Interface screenshots
```

## Roadmap

The PoC covers the library, Analyze, a five-step Create wizard, the form editor with live English and YAML, Validate, and Live analysis on simulated data.

Next up:

- Broader form support for Python and SQL rule bodies, not just analyze-only
- Pluggable real-data adapters (read-only), after replay of sanitized samples
- Correlation-rule support and a coverage map (for example MITRE ATT&CK)
- Git integration so generated files can go out as a pull request to your detections repo
- Hardening for a team deployment (SSO at the proxy, audit logging, container packaging)

A later, optional v2 may add AI assistance (rephrasing explanations, suggested tuning, natural-language drafts). That stays off by default: the deterministic English remains the source of truth, and no rule content leaves your environment without an explicit admin choice.

## Contributing

Issues and pull requests are welcome.

- Keep v1 deterministic: no LLM calls, no "best guess" explanations.
- Don't add cloud services, CDNs, or telemetry. The app should keep running fully offline.
- Never commit secrets, API tokens, or real event data. The PoC uses simulated events only.
- Match the existing style: Python standard library on the server, plain JavaScript in the UI.

## Author

Timothy English, CISSP, CEH, CHFI, Cybersecurity Researcher

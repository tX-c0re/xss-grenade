```
▒██   ██▒  ██████   ██████      ▄████  ██▀███  ▓█████  ███▄    █  ▄▄▄      ▓█████▄ ▓█████ 
▒▒ █ █ ▒░▒██    ▒ ▒██    ▒     ██▒ ▀█▒▓██ ▒ ██▒▓█   ▀  ██ ▀█   █ ▒████▄    ▒██▀ ██▌▓█   ▀ 
░░  █   ░░ ▓██▄   ░ ▓██▄      ▒██░▄▄▄░▓██ ░▄█ ▒▒███   ▓██  ▀█ ██▒▒██  ▀█▄  ░██   █▌▒███   
 ░ █ █ ▒   ▒   ██▒  ▒   ██▒   ░▓█  ██▓▒██▀▀█▄  ▒▓█  ▄ ▓██▒  ▐▌██▒░██▄▄▄▄██ ░▓█▄   ▌▒▓█  ▄ 
▒██▒ ▒██▒▒██████▒▒▒██████▒▒   ░▒▓███▀▒░██▓ ▒██▒░▒████▒▒██░   ▓██░ ▓█   ▓██▒░▒████▓ ░▒████▒
▒▒ ░ ░▓ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░    ░▒   ▒ ░ ▒▓ ░▒▓░░░ ▒░ ░░ ▒░   ▒ ▒  ▒▒   ▓▒█░ ▒▒▓  ▒ ░░ ▒░ ░
░░   ░▒ ░░ ░▒  ░ ░░ ░▒  ░ ░     ░   ░   ░▒ ░ ▒░ ░ ░  ░░ ░░   ░ ▒░  ▒   ▒▒ ░ ░ ▒  ▒  ░ ░  ░
 ░    ░  ░  ░  ░  ░  ░  ░     ░ ░   ░   ░░   ░    ░      ░   ░ ░   ░   ▒    ░ ░  ░    ░   
 ░    ░        ░        ░           ░    ░        ░  ░         ░       ░  ░   ░       ░  ░
                                                                            ░             
                     B r o w s e r - v e r i f i e d   X S S   ·   T X - C 0 R E
```

![License: GPLv3](https://img.shields.io/badge/License-GPLv3-c0392b?style=flat-square)
![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-1f6feb?style=flat-square&logo=python&logoColor=white)
![GUI: PyQt5](https://img.shields.io/badge/GUI-PyQt5-2ecc71?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%C2%B7%20Linux%20%C2%B7%20macOS-4b5563?style=flat-square)
![Status: active](https://img.shields.io/badge/status-active-16a34a?style=flat-square)

> **A modern XSS detection engine for authorized security testing and bug-bounty research.**
> It goes well beyond reflected-payload fuzzing: context-aware injection, **real-browser
> headless verification** to cut false positives, static JavaScript taint analysis, and detection
> of modern client-side classes — DOM XSS, mutation XSS, prototype pollution, DOM clobbering,
> Trusted Types misconfig, SSR hydration, and known-CVE libraries.

It runs as a PyQt5 desktop app — a live attack-surface graph, real-time findings, browser verification, and one-click reports, all from the GUI.

![XSS Grenade — the GUI with its live attack-surface graph and browser-verified findings](assets/screenshot.jpg)

> [!WARNING]
> **Authorized use only.** Test only systems you own or have explicit written permission to test (an in-scope bug-bounty program or a signed engagement). Unauthorized scanning is illegal in most jurisdictions — you are responsible for how you use it.

---

## ▸ Why it hits harder

- **`[+]` Context-aware payloads** — detects *where* a parameter reflects (HTML / attribute / URL / JS / style / comment) and fires only the payloads that fit that context, including multiple reflection contexts for the same parameter.
- **`[+]` Real-browser verification** — confirms candidates in headless Chromium (Playwright), so the report holds **exploitable** issues, not a wall of maybes.
- **`[+]` Static JS taint analysis** — parses JavaScript to an AST and traces untrusted sources (`location.*`, `document.referrer`, `window.name`, `postMessage`, …) into dangerous sinks (`innerHTML`, `eval`, `document.write`, framework sinks).
- **`[+]` Modern classes** — DOM XSS, mutation XSS (mXSS), prototype pollution → gadget chains, DOM clobbering, Trusted Types misconfig, SSR hydration, CSP-bypass analysis.
- **`[+]` Bug-bounty vectors** — `postMessage` handlers with weak `origin` checks, JSONP callback injection, dangling-markup (scriptless, CSP-resistant), SVG/XML content-type reflection.
- **`[+]` Known-CVE library detection** — fingerprints front-end libs/frameworks (React, Vue, Angular, Next.js, jQuery, lodash, DOMPurify, …) and flags versions with known XSS/RCE CVEs.
- **`[+]` Resilient long scans** — atomic, fingerprinted checkpoints resume an interrupted scan instead of starting over.
- **`[+]` Reporting** — one-click **SAVE** → machine-readable JSON, a self-contained client-ready HTML report, and a PoC bundle.

---

## ▸ Requirements

- **Python 3.8+**
- Required: `PyQt5` (the GUI), `requests`, `beautifulsoup4`, `alive-progress`
- Strongly recommended: `esprima` (static JS analysis), `playwright` + Chromium (headless verification)
- Optional: `curl_cffi` (TLS fingerprint evasion)

Recommended/optional deps degrade gracefully — if one is missing, that detection feature is disabled and the rest keeps working. `pip install -r requirements.txt` installs everything.

---

## ▸ Install

```bash
# clone
git clone https://github.com/tX-c0re/xss-grenade.git
cd xss-grenade

# (recommended) virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# dependencies
pip install -r requirements.txt

# (recommended) Chromium for headless verification
playwright install chromium
```

---

## ▸ Run

```bash
python xss_grenade_gui.py
```

```
[1] enter a TARGET URL you are authorized to test
[2] pick your detection modules in the SETTINGS tab   (reflected XSS + crawl are on by default)
[3] hit RUN   → live attack-surface graph + real-time, browser-verified findings
[4] hit SAVE  → JSON + HTML report + a self-contained PoC bundle
```

Findings are confirmed in a real browser — so what lands in RESULTS is exploitable, not noise.

> [!TIP]
> **⚡ Want the fastest scan?** Turn on **`Fast scan (smart payloads)`** in the **SETTINGS** tab.
> It swaps the full payload list for a curated, high-signal set — cutting scan time on large
> targets **from hours to minutes** while keeping broad coverage. Recommended for a quick first pass.

---

## ▸ Detection modules

Reflected/context-aware XSS and crawling run by default; everything else is an opt-in toggle in the **SETTINGS** tab, so you only pay for what you need.

| Area | Phase / toggle | What it does |
|------|--------------|--------------|
| Crawl | `crawl` (default) | Discovers URLs, query params, forms, JSON bodies, and REST/SPA endpoints from JS bundles. |
| Reflected XSS | `context` (default) | Context-aware payloads per reflection point (HTML/attr/URL/JS/style), incl. multiple contexts. |
| Fast scan | `smart payloads` | Curated high-signal payload set — big speed-up on large targets with broad coverage kept. |
| Fuzzing | `--fuzz` | WAF-aware payload mutation when context-aware testing isn't enough. |
| Stored XSS | `--stored`, `--stored-roundtrip` | Detects persisted/round-trip stored XSS. |
| DOM XSS | `--dom`, `--dom-v` | Runtime + static source→sink taint analysis. |
| Static JS | `--static-js` | AST taint analysis of JavaScript bundles and inline scripts. |
| postMessage | `--postmessage` | Flags `message` handlers that flow `event.data` to a sink with missing/weak `origin` validation. |
| Mutation XSS | (automatic) | Sanitizer-bypass / re-parse (mXSS) analysis; runs when the module is available. |
| Prototype pollution | `--proto-pollution` | Client-side PP sources → known library gadget chains → XSS. |
| DOM clobbering | `--dom-clobbering` | Named-element clobbering that hijacks script behavior. |
| Trusted Types | `--trusted-types` | Insecure CSP Trusted Types config + unsafe `createPolicy()`. |
| SSR hydration | `--ssr-hydration` | Server-side-render / hydration XSS issues. |
| CSP bypass | `--csp-bypass` | JSONP-whitelist bypass, `unsafe-inline`/`eval`, missing `base-uri`, nonce reuse, wildcard hosts. |
| Library CVEs | (with `--static-js`) | Fingerprints libraries/frameworks and flags versions with known CVEs. |
| Open redirect → XSS | `--open-redirect` | `javascript:` redirect chains. |
| JSONP injection | `--jsonp-scan` | `?callback=` reflected as a function call in a JS content-type response. |
| Dangling markup | `--dangling-scan` | Unclosed-tag markup-swallowing (scriptless, works even under CSP). |
| SVG / XML XSS | `--svg-scan` | Reflection into `image/svg+xml` / `application/xml` that executes on direct access. |
| WebSocket | `--websocket` | WebSocket message-injection XSS. |
| Headers / CORS | `--headers`, CORS/CRLF/XSSI | Header-reflected XSS, CORS misconfig, CRLF, XSSI. |

Every module above is a checkbox in the GUI's **SETTINGS** tab, with a plain-English explanation in the **HELP** tab.

---

## ▸ Reports

One-click **SAVE** writes a report bundle to a folder of your choice, anytime — even mid-scan or after a stop, so findings are never lost:

- **JSON** — `findings` (confirmed, deduplicated), a `summary` block with a severity breakdown, plus per-category structured findings. Ideal for tooling.
- **HTML** — a single self-contained file (inline CSS, no external assets): severity summary, findings grouped critical-first, per-context remediation, and a vulnerable-library table. All values are HTML-escaped, so the report opens safely even when it holds live payloads.
- **PoC bundle** — a self-contained, inert proof-of-concept page for each confirmed finding.

---

## ▸ Safety

- **Destructive mode** is gated behind explicit confirmation and off by default. Use it only where you may trigger state-changing actions.
- **SSRF scanning** is opt-in for the same reason.
- A single dedup + verification chokepoint runs before anything is reported, so the same issue across many URLs collapses to one finding.

---

## ▸ Project layout

```
xss_grenade.py                # Core scan engine (pipeline, phases, reporting)
xss_grenade_gui.py            # PyQt5 graphical interface
context_engine.py             # Reflection-context classification
_static_js_analyzer.py        # JavaScript AST taint analysis
_dom_v6.py                    # DOM XSS (runtime hooks + static)
_mutation_xss.py              # Mutation XSS payloads/analysis
_proto_pollution_analyzer.py  # Prototype pollution → gadget chains
_dom_clobbering.py            # DOM clobbering
_trusted_types_analyzer.py    # Trusted Types / CSP audit
_template_injection.py        # Client-side template injection (framework-aware)
_library_cve_feed.py          # Library/framework fingerprinting + CVE matching
_dompurify_cve_feed.py        # DOMPurify version → CVE feed
_open_redirect.py             # Open-redirect → XSS
_headless_verifier.py         # Playwright headless verification
_checkpoint.py                # Resume/checkpoint
_html_report.py               # HTML report generation
bench_firingrange/            # Google Firing Range benchmark harness (Apache-2.0)
```

---

## ▸ Contributing

Issues and pull requests welcome. When adding a detection module, include a regression test and keep risky/active scanning behind an explicit opt-in toggle.

---

## ▸ License

Free software under the **GNU General Public License v3.0** — see [LICENSE](LICENSE).

Use it, study it, share it, modify it. If you distribute a modified version, you must release your changes under the GPLv3 too — so the tool stays free and open for everyone.

    XSS Grenade — a modern XSS detection engine for authorized security testing.
    Copyright (C) 2026  TX-C0RE Security Research

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

The bundled Firing Range corpus under `bench_firingrange/templates/` is derived from Google's Firing Range (Apache License 2.0 — see `bench_firingrange/LICENSE.firing-range`), which is GPLv3-compatible.

---

## ▸ Disclaimer

XSS Grenade is provided for lawful, authorized security testing and education only. The authors accept no liability for misuse or for any damage caused by this software. Always obtain explicit permission before testing any system you do not own.

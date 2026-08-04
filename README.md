<p align="center">
  <img src="assets/xss_grenade.png" alt="XSS Grenade — automated XSS vulnerability scanner" width="860">
</p>

<h1 align="center">🔐 XSS Grenade</h1>

<p align="center">
  <b>Next-generation XSS detection engine for modern web applications.</b><br>
  Built for real-world security testing — not just payload fuzzing.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-GPLv3-c0392b?style=flat-square" alt="License: GPLv3">
  <img src="https://img.shields.io/badge/Python-3.8%2B-1f6feb?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/GUI-PyQt5-2ecc71?style=flat-square" alt="GUI: PyQt5">
  <img src="https://img.shields.io/badge/Platform-Windows%20%C2%B7%20Linux%20%C2%B7%20macOS-4b5563?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/status-active-16a34a?style=flat-square" alt="Status: active">
</p>

---

> [!WARNING]
> **Authorized use only.** Test only systems you own or have explicit written permission to test — an in-scope bug-bounty program or a signed engagement. Unauthorized scanning is illegal in most jurisdictions, and **you** are responsible for how you use this tool.

---

## 🚀 Why XSS Grenade?

Most scanners stop at **reflections** — "your input came back in the page." XSS Grenade goes further and confirms **real, exploitable vulnerabilities** in a real browser.

- 🧠 **Context-aware payload engine** — HTML / attribute / URL / JS / CSS / comment
- 🌐 **Built for modern apps** — SPAs, React, Angular, Vue, SSR / hydration
- 🔍 **Finds real attack vectors** — not just echoed payloads
- ⚡ **Headless-browser verification** — cuts false positives to near zero
- 💣 **Bug-bounty focused** — the vectors that actually pay out

> [!NOTE]
> **New to XSS?** Cross-Site Scripting is when an app renders attacker-controlled input as active code in a victim's browser. A "reflection" only means your input *appeared* in the response — it isn't a bug until it actually **executes**. XSS Grenade does that last, hard step for you: it loads the page in a real headless Chromium and checks whether the payload *fires*.

---

## 🧬 What makes it different

| | |
|---|---|
| **Context-aware injection** | Detects *where* a parameter lands and fires only the payloads that fit that context — including multiple contexts for the same parameter. |
| **Real-browser verification** | Candidates are re-loaded in headless Chromium (Playwright). Only findings that actually execute survive. |
| **Static JS taint analysis** | Parses JavaScript to an AST and traces untrusted sources (`location.*`, `document.referrer`, `window.name`, `postMessage`) into dangerous sinks (`innerHTML`, `eval`, `document.write`, framework sinks). |
| **Modern vulnerability classes** | DOM XSS · mutation XSS (mXSS) · prototype pollution → XSS · DOM clobbering · Trusted Types misconfig · SSR hydration issues. |
| **Bug-bounty vectors** | `postMessage` abuse · JSONP callback injection · dangling markup (scriptless, CSP-resistant) · SVG/XML content-type reflection. |
| **Known-CVE library detection** | Fingerprints React, Vue, Angular, Next.js, jQuery, lodash, DOMPurify… and flags versions with known XSS/RCE CVEs. |

---

## 🖥️ Interface preview

<p align="center">
  <img src="assets/screenshot.jpg" alt="XSS Grenade GUI — live attack-surface graph, real-time findings, browser-verified results" width="960">
</p>

A live attack-surface graph, real-time severity-ranked findings, and browser-verified results — all from a single PyQt5 desktop app.

---

## ⚡ Quick start

```bash
git clone https://github.com/tX-c0re/xss-grenade.git
cd xss-grenade

python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate

pip install -r requirements.txt
python -m playwright install chromium   # for headless verification

python xss_grenade_gui.py
```

> [!TIP]
> No login? No problem — but ~80% of interesting XSS hides behind authentication. Paste your session cookies in **SETTINGS → Authentication** to scan admin panels, profiles and dashboards. Cookies stay in memory only — never written to reports or logs.

---

## 🎯 Usage

1. **Enter the target URL** in the top bar.
2. **Pick your modules** in the **SETTINGS** tab (or keep the sensible defaults).
3. Click **RUN**.
4. **Watch findings appear in real time** — the attack-surface graph and the FINDINGS table update live.
5. **Export** the report: **SAVE** → JSON + HTML + PoC bundle.

✔ Findings are verified in a real browser &nbsp;•&nbsp; ✔ Output is *exploitable* vulnerabilities, not noise.

### ⚡ Fast Scan mode

Enable **“Smart Payloads”** for a quick, high-signal first pass:

- ⚡ Cuts scan time from **hours → minutes**
- 🎯 Keeps high-signal, per-context coverage
- 💡 Ideal for first-pass recon before a deep run

---

## 🧪 Detection modules

Fully modular — enable only what you need.

| Category | Capability |
|---|---|
| **Crawl** | SPA-aware endpoint & parameter discovery (sitemap, forms, XHR, hash routes) |
| **Reflected XSS** | Context-aware payload injection + breakout synthesis |
| **DOM XSS** | Runtime (headless) **and** static JS taint analysis |
| **Stored XSS** | Multi-canary round-trip detection |
| **Prototype Pollution** | Client-side sources → known gadget chains → XSS |
| **CSP Bypass** | Misconfig detection + JSONP / `unsafe-inline` / nonce-reuse bypasses |
| **postMessage** | Weak or absent `origin` validation → sink |
| **JSONP** | Callback-parameter injection |
| **SVG / XML** | Content-type–driven reflection |
| **WebSocket** | `onmessage` handlers with DOM sinks |
| **Headers / CORS** | Header reflection + CORS misconfiguration |
| **Library CVEs** | Vulnerable front-end library / framework versions |

---

## 📊 Reports

One-click export, three formats:

- **JSON** — structured, automation-ready
- **HTML** — self-contained, client-ready report
- **PoC bundle** — reproducible, copy-paste exploit examples

✔ Deduplicated &nbsp;•&nbsp; ✔ Severity-ranked &nbsp;•&nbsp; ✔ Safe to open (payloads escaped in the report)

---

## 🛡️ Safety

- **Destructive testing is off by default** — you opt in explicitly.
- **SSRF scanning is opt-in.**
- Every finding passes a **verification checkpoint** before it's reported.
- Designed to **minimise noise and risk** — reproducible results over a wall of maybes.

---

## 🧱 Project structure

```text
xss_grenade.py                 # Core scan engine (CLI + orchestration)
xss_grenade_gui.py             # PyQt5 desktop GUI
context_engine.py              # Reflection-context detection
_static_js_analyzer.py         # JavaScript source → sink taint analysis
_dom_v6.py                     # DOM XSS (headless taint)
_mutation_xss.py               # Mutation XSS (mXSS)
_proto_pollution_analyzer.py   # Prototype pollution → gadget chains
_dom_clobbering.py             # DOM clobbering
_trusted_types_analyzer.py     # Trusted Types / CSP audit
_headless_verifier.py          # Real-browser confirmation (Playwright)
_html_report.py                # Self-contained HTML report
```

---

## 🧭 Roadmap

- [ ] Headless-verification improvements
- [ ] AI-assisted, context-driven payload generation
- [ ] Burp Suite integration
- [ ] Distributed / parallel scanning

---

## 🤝 Contributing

Pull requests welcome. To keep the project sharp and safe:

- Keep risky features **behind an opt-in toggle**.
- Include **regression tests** for new detections.
- Focus on **real-world attack vectors**, not payload-count vanity.

---

## ⚖️ License

**GNU GPLv3** — free and open source. If you modify and distribute it, you must keep it open. See [`LICENSE`](LICENSE).

---

## ⚠️ Disclaimer

For **authorized security testing only**. You are solely responsible for how you use this tool; unauthorized use may be illegal.

<p align="center">
  <sub>TX-C0RE Security Research · <a href="https://github.com/tX-c0re">github.com/tX-c0re</a></sub>
</p>

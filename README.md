<p align="center"> <img src="assets/xss_grenade.png" alt="XSS Grenade — automated XSS vulnerability scanner" width="860"> </p>

<h1 align="center">🔐 XSS Grenade</h1>

<p align="center"> <strong>Next-generation XSS detection engine for modern web applications</strong><br> Built for real-world security testing — not just payload fuzzing. </p>

<p align="center"> <img src="https://img.shields.io/badge/License-GPLv3-c0392b?style=flat-square"> <img src="https://img.shields.io/badge/Python-3.8%2B-1f6feb?style=flat-square&logo=python&logoColor=white"> <img src="https://img.shields.io/badge/GUI-PyQt5-2ecc71?style=flat-square"> <img src="https://img.shields.io/badge/Platform-Windows%20%C2%B7%20Linux%20%C2%B7%20macOS-4b5563?style=flat-square"> <img src="https://img.shields.io/badge/status-active-16a34a?style=flat-square"> </p>

🚀 Why XSS Grenade?

Most scanners find reflections.
XSS Grenade finds real, exploitable vulnerabilities.

🧠 Context-aware payload engine (HTML / JS / DOM / attributes)
🌐 Designed for modern apps (SPA, React, Angular, SSR)
🔍 Detects real attack vectors — not just payload echoes
⚡ Headless browser verification (no false positives)
💣 Focused on bug bounty & real-world exploitation
🧬 What makes it different
Context-aware injection — payloads adapted to reflection context
Real-browser verification — only exploitable findings survive
Static JS taint analysis — source → sink tracing
Modern vulnerability classes:
DOM XSS
Mutation XSS (mXSS)
Prototype pollution → XSS
DOM clobbering
Trusted Types misconfig
SSR hydration issues
Bug bounty vectors:
postMessage abuse
JSONP injection
dangling markup
Library CVE detection — React, Vue, Angular, jQuery, lodash, DOMPurify…
🖥️ Interface Preview

<p align="center"> <img src="assets/screenshot.jpg" width="900"> </p>

Live attack surface graph, real-time findings, and browser-verified results — all in a PyQt5 GUI.

⚡ Quick Start
git clone https://github.com/tX-c0re/xss-grenade.git
cd xss-grenade

python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt
python -m playwright install chromium

python xss_grenade_gui.py
🎯 Usage
[1] Enter target URL
[2] Select modules (SETTINGS tab)
[3] Click RUN
[4] Review findings in real-time
[5] Export report (JSON + HTML + PoC)

✔ Findings are verified in a real browser
✔ Output = exploitable vulnerabilities, not noise

⚡ Fast Scan Mode

Enable “Smart Payloads”:

⚡ Reduces scan time from hours → minutes
🎯 Keeps high-signal coverage
💡 Perfect for first-pass reconnaissance
🧪 Detection Modules

Fully modular — enable only what you need.

Category	Capability
Crawl	SPA-aware endpoint discovery
Reflected XSS	Context-aware payload injection
DOM XSS	Runtime + static taint analysis
Stored XSS	Round-trip detection
Prototype Pollution	Gadget chains → XSS
CSP Bypass	Misconfig + bypass detection
postMessage	Weak origin validation
JSONP	Callback injection
SVG/XML	Content-type based XSS
WebSocket	Message injection
Headers/CORS	Reflection + misconfig
📊 Reports

One-click export:

JSON → automation-ready structured data
HTML → client-ready report (self-contained)
PoC bundle → reproducible exploit examples

✔ Deduplicated
✔ Severity-ranked
✔ Safe to open (escaped payloads)

🛡️ Safety
Destructive testing is disabled by default
SSRF scanning is opt-in
Findings pass a verification checkpoint
Designed to minimize noise & risk
🧱 Project Structure
xss_grenade.py            # Core engine
xss_grenade_gui.py        # GUI
context_engine.py         # Context detection
_static_js_analyzer.py    # JS taint analysis
_dom_v6.py                # DOM XSS
_mutation_xss.py          # mXSS
_proto_pollution_analyzer.py
_dom_clobbering.py
_trusted_types_analyzer.py
_headless_verifier.py
_html_report.py
🧭 Roadmap

Headless browser improvements

AI-assisted payload generation

Burp Suite integration

Distributed scanning

🤝 Contributing

Pull requests welcome.

Keep risky features behind opt-in
Include regression tests
Focus on real-world attack vectors
⚖️ License

GNU GPLv3 — free and open.

If you modify and distribute it, you must keep it open.

⚠️ Disclaimer

For authorized security testing only.

You are responsible for how you use this tool.
Unauthorized use may be illegal.
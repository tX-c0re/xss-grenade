// ════════════════════════════════════════════════════════════════════════════
// XSS Grenade — DOM v6 hooks (taint-aware source/sink tracking)
// ════════════════════════════════════════════════════════════════════════════
//
// Nahrazuje původní dom_hooks.js. Přidává:
//   - SOURCE tracking (location.*, document.URL, .referrer, window.name,
//     cookie, localStorage, postMessage, fragment hash)
//   - Taint propagation přes WeakRef + ghost wrapping
//   - SINK detection s chain (source → ops → sink)
//   - Auto-interaction trigger (click/hover/focus/submit/change)
//   - Per-canary detection (multiple canaries simultaneously)
//
// Placeholders:
//   __XSS_MARKERS_PLACEHOLDER__  = JSON array of canary tokens to watch
//   __XSS_AUTO_INTERACT__        = "true" / "false"
// ════════════════════════════════════════════════════════════════════════════

(function () {
    'use strict';

    // ── State exposed to Python via page.evaluate() ─────────────────────────
    window.__xssg_state__ = {
        markers: __XSS_MARKERS_PLACEHOLDER__,        // array of canary tokens
        sink_hits: [],          // {sink, value, marker_matches, source_origin?, stack, ts}
        source_reads: [],       // {source, value, ts} - kdo četl source
        taint_chains: [],       // {source, sink, value, ops, ts} - úplný chain
        triggered: false,       // alespoň jeden marker landed in sink
        triggered_by: null,     // first marker, který vyhrál
        dialogs: [],            // {fn, message, ts}
        page_errors: [],        // window.onerror
        csp_violations: [],
        interactions_done: 0,   // kolik click/hover/etc. jsme provedli
        tt_policies: [],        // Trusted Types policies registered at runtime + pass-through probe
    };

    var S = window.__xssg_state__;
    var MARKERS = (S.markers && S.markers.length) ? S.markers : ['__XSS_NOMARKER__'];

    // ── Pomocná funkce: která canaries je v hodnotě ─────────────────────────
    function findMarkers(str) {
        var matches = [];
        try {
            var s = String(str);
            for (var i = 0; i < MARKERS.length; i++) {
                if (s.indexOf(MARKERS[i]) !== -1) matches.push(MARKERS[i]);
            }
        } catch (e) { }
        return matches;
    }

    // ── Source specificity ranking (for taint-chain attribution) ────────────
    // The canary sits in the URL, so every location.* read matches it. Rank the
    // more specific / higher-signal sources above the generic location reads so
    // the reconstructed chain names the real origin, not the last URL read.
    function _srcRank(name) {
        name = String(name || '');
        if (name.indexOf('postMessage') !== -1) return 5;
        if (name.indexOf('localStorage') !== -1 ||
            name.indexOf('sessionStorage') !== -1) return 4;
        if (name.indexOf('window.name') !== -1 ||
            name.indexOf('cookie') !== -1) return 4;
        if (name.indexOf('searchParams') !== -1 ||
            name.indexOf('URLSearchParams') !== -1) return 3;
        if (name.indexOf('hash') !== -1 || name.indexOf('search') !== -1) return 2;
        return 1;   // raw location.href / document.URL / referrer — least specific
    }

    // ── Pomocná funkce: zaznamenej sink hit ─────────────────────────────────
    function recordSink(sinkName, rawValue, sourceOrigin) {
        try {
            var str = String(rawValue);
            var marker_matches = findMarkers(str);
            var record = {
                sink: sinkName,
                value: str.substring(0, 300),
                marker_matches: marker_matches,
                source_origin: sourceOrigin || null,
                stack: null,
                ts: Date.now()
            };
            try {
                var e = new Error();
                if (e.stack) {
                    record.stack = String(e.stack).split('\n').slice(2, 6).join(' | ');
                }
            } catch (_) { }
            S.sink_hits.push(record);
            if (marker_matches.length > 0) {
                S.triggered = true;
                if (!S.triggered_by) S.triggered_by = marker_matches[0];
                // ── TAINT CHAIN: dohledej source read se stejným markerem ──
                // v10.79 fix: the canary is injected into the URL, so EVERY read
                // of location.href/.search/.hash/document.URL contains it. The old
                // "newest match wins" attributed the chain to whatever generic
                // location read happened last. Prefer the MOST SPECIFIC source
                // (postMessage/storage/searchParams over raw location.*); ties go
                // to the most recent.
                var src = null, srcRank = -1;
                for (var i = S.source_reads.length - 1; i >= 0; i--) {
                    var r = S.source_reads[i];
                    var s_str = String(r.value || '');
                    var hit = false;
                    for (var j = 0; j < marker_matches.length; j++) {
                        if (s_str.indexOf(marker_matches[j]) !== -1) { hit = true; break; }
                    }
                    if (hit) {
                        var rk = _srcRank(r.source);
                        if (rk > srcRank) { src = r; srcRank = rk; }
                    }
                }
                if (src) {
                    S.taint_chains.push({
                        source: src.source,
                        sink: sinkName,
                        marker: marker_matches[0],
                        chain_value: str.substring(0, 200),
                        delta_ms: record.ts - src.ts,
                        ts: record.ts
                    });
                }
            }
        } catch (e) { }
    }

    // ── Pomocná funkce: zaznamenej source read ──────────────────────────────
    function recordSource(sourceName, value) {
        try {
            var str = String(value || '');
            // Skipni triviální čtení (např. window.location v každém eventu)
            // — log jen když hodnota obsahuje něco, co by mohlo být zajímavé:
            // canary marker, # fragment, ? query, nebo je delší než 5 znaků
            var has_marker = findMarkers(str).length > 0;
            var has_query = str.indexOf('?') !== -1 || str.indexOf('#') !== -1;
            if (!has_marker && !has_query && str.length < 5) return;
            S.source_reads.push({
                source: sourceName,
                value: str.substring(0, 300),
                has_marker: has_marker,
                ts: Date.now()
            });
            // Cap source_reads na 200 záznamů (anti-flood).
            // v10.79 fix: NEVER evict a marker-bearing read — it is the taint
            // origin the chain reconstruction needs. A page that polls
            // location/storage in a rAF/timer loop can push the canary read past
            // the 200-cap and the old blind splice dropped it, losing the chain.
            // Drop only the oldest UNMARKED entries.
            if (S.source_reads.length > 200) {
                var _over = S.source_reads.length - 200;
                var _kept = [];
                for (var _k = 0; _k < S.source_reads.length; _k++) {
                    var _e = S.source_reads[_k];
                    if (_over > 0 && !_e.has_marker) { _over--; continue; }
                    _kept.push(_e);
                }
                S.source_reads = _kept;
            }
        } catch (e) { }
    }

    // ════════════════════════════════════════════════════════════════════════
    // TRUSTED TYPES — runtime policy audit
    // ════════════════════════════════════════════════════════════════════════
    // The static analyzer reads createPolicy() SOURCE; it can't tell what a
    // minified/obfuscated transformer actually DOES. Here we wrap createPolicy
    // BEFORE page scripts run, and for every registered policy we PROBE its
    // transformers with a dangerous string — if the output comes back unchanged
    // the policy is a pass-through (a no-op sanitizer). A pass-through 'default'
    // policy is a silent backdoor: it satisfies Trusted Types enforcement for
    // EVERY sink on the page while sanitizing nothing.
    try {
        var _TT = window.trustedTypes;
        if (_TT && typeof _TT.createPolicy === 'function') {
            var _origCreatePolicy = _TT.createPolicy.bind(_TT);
            _TT.createPolicy = function (name, rules) {
                var policy = _origCreatePolicy(name, rules);
                try {
                    var rec = {
                        name: String(name),
                        has_createHTML: false, has_createScript: false,
                        has_createScriptURL: false,
                        passthrough_html: null, passthrough_script: null,
                        passthrough_scripturl: null, ts: Date.now()
                    };
                    if (policy && typeof policy.createHTML === 'function') {
                        rec.has_createHTML = true;
                        try {
                            var oH = String(policy.createHTML('<img src=x onerror=__ttprobe__>'));
                            rec.passthrough_html =
                                (oH.indexOf('onerror') !== -1 && oH.indexOf('<img') !== -1);
                        } catch (e) { rec.passthrough_html = null; }
                    }
                    if (policy && typeof policy.createScript === 'function') {
                        rec.has_createScript = true;
                        try {
                            var oS = String(policy.createScript('__ttprobe__()'));
                            rec.passthrough_script = (oS.indexOf('__ttprobe__') !== -1);
                        } catch (e) { rec.passthrough_script = null; }
                    }
                    if (policy && typeof policy.createScriptURL === 'function') {
                        rec.has_createScriptURL = true;
                        try {
                            var oU = String(policy.createScriptURL('https://xssg-tt.invalid/x.js'));
                            rec.passthrough_scripturl = (oU.indexOf('xssg-tt.invalid') !== -1);
                        } catch (e) { rec.passthrough_scripturl = null; }
                    }
                    S.tt_policies.push(rec);
                } catch (e) { }
                return policy;
            };
        }
    } catch (e) { }

    // ════════════════════════════════════════════════════════════════════════
    // SOURCES — hookni gettery na známé tainted sources
    // ════════════════════════════════════════════════════════════════════════

    // location.href, location.search, location.hash, location.pathname
    function hookLocationProperty(propName) {
        try {
            var origGetter = Object.getOwnPropertyDescriptor(Location.prototype, propName);
            if (!origGetter || !origGetter.get) return;
            var origGet = origGetter.get;
            Object.defineProperty(Location.prototype, propName, {
                get: function () {
                    var v = origGet.call(this);
                    recordSource('location.' + propName, v);
                    return v;
                },
                set: origGetter.set,
                configurable: true
            });
        } catch (e) { }
    }
    hookLocationProperty('href');
    hookLocationProperty('search');
    hookLocationProperty('hash');
    hookLocationProperty('pathname');

    // document.URL, document.documentURI, document.referrer
    function hookDocumentProperty(propName) {
        try {
            var origGetter = Object.getOwnPropertyDescriptor(Document.prototype, propName);
            if (!origGetter || !origGetter.get) return;
            var origGet = origGetter.get;
            Object.defineProperty(Document.prototype, propName, {
                get: function () {
                    var v = origGet.call(this);
                    recordSource('document.' + propName, v);
                    return v;
                },
                set: origGetter.set,
                configurable: true
            });
        } catch (e) { }
    }
    hookDocumentProperty('URL');
    hookDocumentProperty('documentURI');
    hookDocumentProperty('referrer');
    hookDocumentProperty('cookie');

    // window.name (deprecated source ale stále funkční)
    try {
        var winNameDesc = Object.getOwnPropertyDescriptor(window, 'name');
        if (winNameDesc && winNameDesc.get) {
            var origNameGet = winNameDesc.get;
            Object.defineProperty(window, 'name', {
                get: function () {
                    var v = origNameGet.call(this);
                    recordSource('window.name', v);
                    return v;
                },
                set: winNameDesc.set,
                configurable: true
            });
        }
    } catch (e) { }

    // localStorage / sessionStorage .getItem
    function hookStorage(storage, name) {
        try {
            var origGet = storage.getItem;
            storage.getItem = function (key) {
                var v = origGet.call(this, key);
                if (v !== null) recordSource(name + '.getItem(' + String(key).substring(0, 30) + ')', v);
                return v;
            };
        } catch (e) { }
    }
    // NB: even `typeof localStorage` triggers the Window storage getter, which
    // throws SecurityError on an opaque-origin / sandboxed / storage-partitioned
    // document. Must be guarded — an uncaught throw here would abort the whole
    // IIFE and silently take EVERY sink hook below it with it.
    try {
        if (typeof localStorage !== 'undefined') hookStorage(localStorage, 'localStorage');
    } catch (e) { }
    try {
        if (typeof sessionStorage !== 'undefined') hookStorage(sessionStorage, 'sessionStorage');
    } catch (e) { }

    // postMessage event source
    try {
        window.addEventListener('message', function (ev) {
            try {
                recordSource('postMessage(' + (ev.origin || '?') + ')', JSON.stringify(ev.data));
            } catch (_) { }
        }, true);
    } catch (e) { }

    // URLSearchParams.get — hodně frameworků toto používá pro query parsing
    try {
        if (typeof URLSearchParams !== 'undefined') {
            var origUSPGet = URLSearchParams.prototype.get;
            URLSearchParams.prototype.get = function (key) {
                var v = origUSPGet.call(this, key);
                if (v !== null) recordSource('URLSearchParams.get(' + String(key).substring(0, 30) + ')', v);
                return v;
            };
        }
    } catch (e) { }

    // ════════════════════════════════════════════════════════════════════════
    // SINKS — execute primitives
    // ════════════════════════════════════════════════════════════════════════

    // innerHTML / outerHTML
    function hookInnerOuter(propName) {
        try {
            var d = Object.getOwnPropertyDescriptor(Element.prototype, propName);
            if (!d || !d.set) return;
            var origSet = d.set;
            Object.defineProperty(Element.prototype, propName, {
                set: function (v) {
                    recordSink(propName, v);
                    return origSet.call(this, v);
                },
                get: d.get,
                configurable: true
            });
        } catch (e) { }
    }
    hookInnerOuter('innerHTML');
    hookInnerOuter('outerHTML');

    // ShadowRoot.innerHTML — ShadowRoot extends DocumentFragment (NOT Element),
    // so the Element.prototype setter above NEVER fires for `shadowRoot.innerHTML
    // = …`, the canonical Web-Component sink. ShadowRoot implements the same
    // InnerHTML mixin, so it carries its own innerHTML descriptor to hook.
    try {
        if (typeof ShadowRoot !== 'undefined') {
            var srd = Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'innerHTML');
            if (srd && srd.set) {
                var origSrSet = srd.set;
                Object.defineProperty(ShadowRoot.prototype, 'innerHTML', {
                    set: function (v) {
                        recordSink('shadowRoot.innerHTML', v);
                        return origSrSet.call(this, v);
                    },
                    get: srd.get,
                    configurable: true
                });
            }
        }
    } catch (e) { }

    // insertAdjacentHTML
    try {
        var origInsAdj = Element.prototype.insertAdjacentHTML;
        Element.prototype.insertAdjacentHTML = function (where, html) {
            recordSink('insertAdjacentHTML', html);
            return origInsAdj.call(this, where, html);
        };
    } catch (e) { }

    // eval
    try {
        var origEval = window.eval;
        window.eval = function (code) {
            recordSink('eval', code);
            return origEval.call(this, code);
        };
    } catch (e) { }

    // document.write / writeln
    try {
        var origWrite = document.write;
        document.write = function (content) {
            recordSink('document.write', content);
            return origWrite.apply(this, arguments);
        };
    } catch (e) { }
    try {
        var origWriteln = document.writeln;
        document.writeln = function (content) {
            recordSink('document.writeln', content);
            return origWriteln.apply(this, arguments);
        };
    } catch (e) { }

    // setTimeout / setInterval (string overload)
    try {
        var origSetTimeout = window.setTimeout;
        window.setTimeout = function (handler) {
            if (typeof handler === 'string') recordSink('setTimeout(string)', handler);
            return origSetTimeout.apply(this, arguments);
        };
    } catch (e) { }
    try {
        var origSetInterval = window.setInterval;
        window.setInterval = function (handler) {
            if (typeof handler === 'string') recordSink('setInterval(string)', handler);
            return origSetInterval.apply(this, arguments);
        };
    } catch (e) { }

    // Function constructor
    try {
        var origFunction = window.Function;
        function HookedFunction() {
            var code = Array.prototype.join.call(arguments, ' ');
            recordSink('Function', code);
            return origFunction.apply(this, arguments);
        }
        HookedFunction.prototype = origFunction.prototype;
        window.Function = HookedFunction;
    } catch (e) { }

    // Web Worker / Shared Worker constructor — a tainted script URL loads
    // arbitrary JS in a worker context. Hook the constructor and record the URL.
    try {
        ['Worker', 'SharedWorker'].forEach(function (wn) {
            var Orig = window[wn];
            if (typeof Orig !== 'function') return;
            function HookedWorker(url) {
                recordSink(wn + '(url)', url);
                var a = Array.prototype.slice.call(arguments);
                // forward to the real constructor with `new` + all args
                return new (Function.prototype.bind.apply(Orig, [null].concat(a)))();
            }
            HookedWorker.prototype = Orig.prototype;
            window[wn] = HookedWorker;
        });
    } catch (e) { }

    // Service Worker registration — navigator.serviceWorker.register(url).
    // A SW controls EVERY request in scope and persists across reloads, so a
    // tainted script URL is a persistent, full-origin compromise.
    try {
        if (navigator.serviceWorker &&
            typeof navigator.serviceWorker.register === 'function') {
            var origReg = navigator.serviceWorker.register;
            navigator.serviceWorker.register = function (url) {
                recordSink('serviceWorker.register(url)', url);
                return origReg.apply(this, arguments);
            };
        }
    } catch (e) { }

    // v10.82 DEPTH: dynamic <script> loading — createElement('script'); s.src =
    // taintedUrl; document.head.appendChild(s). This is jQuery's globalEval /
    // $.getScript path and it NEVER reaches window.eval, so it was an un-hooked
    // runtime sink. Taint-gated: record ONLY when the src / inline code carries our
    // canary, so ordinary script loading (analytics, bundles) is never flagged.
    try {
        var sd = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
        if (sd && sd.set) {
            var origScriptSrc = sd.set;
            Object.defineProperty(HTMLScriptElement.prototype, 'src', {
                set: function (v) {
                    try { if (findMarkers(String(v)).length > 0) recordSink('script.src', v); } catch (e) { }
                    return origScriptSrc.call(this, v);
                },
                get: sd.get,
                configurable: true
            });
        }
    } catch (e) { }
    try {
        function __xsg_inspectScript(node) {
            try {
                if (!node || node.tagName !== 'SCRIPT') return;
                var src = node.getAttribute && node.getAttribute('src');
                if (src && findMarkers(String(src)).length > 0)
                    recordSink('appendChild(script.src)', src);
                var txt = node.textContent || '';
                if (txt && findMarkers(String(txt)).length > 0)
                    recordSink('appendChild(script.text)', txt);
            } catch (e) { }
        }
        ['appendChild', 'insertBefore'].forEach(function (m) {
            var orig = Node.prototype[m];
            if (typeof orig !== 'function') return;
            Node.prototype[m] = function (node) {
                __xsg_inspectScript(node);
                return orig.apply(this, arguments);
            };
        });
        if (Element.prototype.append) {
            var origAppend = Element.prototype.append;
            Element.prototype.append = function () {
                for (var i = 0; i < arguments.length; i++) __xsg_inspectScript(arguments[i]);
                return origAppend.apply(this, arguments);
            };
        }
    } catch (e) { }

    // location.href = / location.assign / location.replace - javascript: scheme
    function hookLocationSet(propName) {
        try {
            var d = Object.getOwnPropertyDescriptor(Location.prototype, propName);
            if (!d || !d.set) return;
            var origSet = d.set;
            Object.defineProperty(Location.prototype, propName, {
                set: function (v) {
                    var s = String(v).toLowerCase().trim();
                    if (s.indexOf('javascript:') === 0 || s.indexOf('data:text/html') === 0 || s.indexOf('vbscript:') === 0) {
                        recordSink('location.' + propName + '(scheme)', v);
                    }
                    return origSet.call(this, v);
                },
                get: d.get,
                configurable: true
            });
        } catch (e) { }
    }
    hookLocationSet('href');

    try {
        var origAssign = Location.prototype.assign;
        Location.prototype.assign = function (url) {
            var s = String(url).toLowerCase().trim();
            if (s.indexOf('javascript:') === 0 || s.indexOf('data:text/html') === 0) {
                recordSink('location.assign(scheme)', url);
            }
            return origAssign.call(this, url);
        };
    } catch (e) { }
    try {
        var origReplace = Location.prototype.replace;
        Location.prototype.replace = function (url) {
            var s = String(url).toLowerCase().trim();
            if (s.indexOf('javascript:') === 0 || s.indexOf('data:text/html') === 0) {
                recordSink('location.replace(scheme)', url);
            }
            return origReplace.call(this, url);
        };
    } catch (e) { }

    // <a href="javascript:..."> setter
    try {
        var aHrefDesc = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
        if (aHrefDesc && aHrefDesc.set) {
            var origAHrefSet = aHrefDesc.set;
            Object.defineProperty(HTMLAnchorElement.prototype, 'href', {
                set: function (v) {
                    var s = String(v).toLowerCase().trim();
                    if (s.indexOf('javascript:') === 0) {
                        recordSink('<a>.href(javascript:)', v);
                    }
                    return origAHrefSet.call(this, v);
                },
                get: aHrefDesc.get,
                configurable: true
            });
        }
    } catch (e) { }

    // ── Modern parse-time HTML sinks ────────────────────────────────────────
    // The static analyzer already flags these as sinks, but until now the
    // runtime layer only hooked innerHTML/outerHTML/insertAdjacentHTML/write —
    // so as codebases migrate off innerHTML onto setHTMLUnsafe / srcdoc / the
    // Sanitizer-opt-out APIs, findings were flagged statically but never
    // CONFIRMED headless. Each hook below funnels into recordSink → taint_chain.

    // setHTMLUnsafe (2024 Baseline) — Element + ShadowRoot. Explicit opt-OUT of
    // sanitization, so tainted HTML here executes. (ShadowRoot extends
    // DocumentFragment, so the Element.prototype hooks never covered it.)
    ['Element', 'ShadowRoot'].forEach(function (proto) {
        try {
            var P = window[proto] && window[proto].prototype;
            if (!P || typeof P.setHTMLUnsafe !== 'function') return;
            var origSHU = P.setHTMLUnsafe;
            P.setHTMLUnsafe = function (html) {
                recordSink(proto + '.setHTMLUnsafe', html);
                return origSHU.apply(this, arguments);
            };
        } catch (e) { }
    });

    // Document.parseHTMLUnsafe(html) — static; returns a live Document parsed
    // WITHOUT sanitization.
    try {
        if (typeof Document !== 'undefined' && typeof Document.parseHTMLUnsafe === 'function') {
            var origPHU = Document.parseHTMLUnsafe;
            Document.parseHTMLUnsafe = function (html) {
                recordSink('Document.parseHTMLUnsafe', html);
                return origPHU.apply(this, arguments);
            };
        }
    } catch (e) { }

    // Range.createContextualFragment(html) — parses arbitrary HTML into a
    // fragment; a classic innerHTML-equivalent sink.
    try {
        if (typeof Range !== 'undefined' && Range.prototype.createContextualFragment) {
            var origCCF = Range.prototype.createContextualFragment;
            Range.prototype.createContextualFragment = function (html) {
                recordSink('Range.createContextualFragment', html);
                return origCCF.apply(this, arguments);
            };
        }
    } catch (e) { }

    // DOMParser.parseFromString(str, 'text/html'|xhtml) — parses attacker HTML
    // into a detached document. Only the HTML/XHTML content types matter here.
    try {
        if (typeof DOMParser !== 'undefined' && DOMParser.prototype.parseFromString) {
            var origPFS = DOMParser.prototype.parseFromString;
            DOMParser.prototype.parseFromString = function (str, type) {
                try {
                    var t = String(type || '').toLowerCase();
                    // v10.79 FP fix: only HTML parse types execute (text/html and
                    // application/xhtml+xml — both contain 'html'). The old bare
                    // 'xml' clause also matched benign text/xml / image/svg+xml
                    // data parses and flagged them as confirmed sinks.
                    if (t.indexOf('html') !== -1) {
                        recordSink('DOMParser.parseFromString(' + t + ')', str);
                    }
                } catch (_) { }
                return origPFS.apply(this, arguments);
            };
        }
    } catch (e) { }

    // <iframe srcdoc="..."> setter — inline HTML doc with full script execution.
    try {
        var sdDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
        if (sdDesc && sdDesc.set) {
            var origSd = sdDesc.set;
            Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
                set: function (v) {
                    recordSink('iframe.srcdoc', v);
                    return origSd.call(this, v);
                },
                get: sdDesc.get,
                configurable: true
            });
        }
    } catch (e) { }

    // setAttribute / setAttributeNS — the escape hatch around the property
    // setters above. setAttribute('srcdoc'|on*|href|src|action|formaction|
    // xlink:href, 'javascript:...') bypasses every hook above. Record only the
    // dangerous shapes so benign attribute writes don't flood sink_hits.
    var _URL_ATTRS = { href: 1, src: 1, action: 1, formaction: 1,
                       'xlink:href': 1, poster: 1, data: 1, background: 1 };
    function _sinkForAttr(name, value) {
        try {
            var n = String(name || '').toLowerCase();
            var v = String(value == null ? '' : value);
            if (n === 'srcdoc') { recordSink('setAttribute(srcdoc)', v); return; }
            if (n.indexOf('on') === 0 && n.length > 2) { recordSink('setAttribute(' + n + ')', v); return; }
            if (_URL_ATTRS[n]) {
                var s = v.toLowerCase().trim();
                if (s.indexOf('javascript:') === 0 || s.indexOf('data:text/html') === 0 || s.indexOf('vbscript:') === 0) {
                    recordSink('setAttribute(' + n + ':scheme)', v);
                }
            }
        } catch (_) { }
    }
    try {
        var origSetAttr = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function (name, value) {
            _sinkForAttr(name, value);
            return origSetAttr.apply(this, arguments);
        };
    } catch (e) { }
    try {
        var origSetAttrNS = Element.prototype.setAttributeNS;
        Element.prototype.setAttributeNS = function (ns, name, value) {
            _sinkForAttr(name, value);
            return origSetAttrNS.apply(this, arguments);
        };
    } catch (e) { }

    // ════════════════════════════════════════════════════════════════════════
    // DIALOGS — alert / confirm / prompt
    // ════════════════════════════════════════════════════════════════════════

    ['alert', 'confirm', 'prompt'].forEach(function (fn) {
        try {
            var orig = window[fn];
            window[fn] = function (msg) {
                S.dialogs.push({
                    fn: fn,
                    message: msg === undefined ? '' : String(msg).substring(0, 300),
                    marker_matches: findMarkers(msg),
                    ts: Date.now()
                });
                if (findMarkers(msg).length > 0) {
                    S.triggered = true;
                    if (!S.triggered_by) S.triggered_by = findMarkers(msg)[0];
                }
                // Don't actually show — would block headless
                return undefined;
            };
        } catch (e) { }
    });

    // ════════════════════════════════════════════════════════════════════════
    // ERROR + CSP MONITORING
    // ════════════════════════════════════════════════════════════════════════

    try {
        window.addEventListener('error', function (ev) {
            try {
                S.page_errors.push({
                    message: String(ev.message || ev.error || ev).substring(0, 300),
                    file: ev.filename || '',
                    line: ev.lineno || 0,
                    ts: Date.now()
                });
            } catch (_) { }
        });
    } catch (e) { }

    try {
        document.addEventListener('securitypolicyviolation', function (e) {
            S.csp_violations.push({
                directive: e.violatedDirective,
                blocked: e.blockedURI,
                source: e.sourceFile,
                line: e.lineNumber,
                sample: e.sample ? String(e.sample).substring(0, 200) : null,
                ts: Date.now()
            });
        });
    } catch (e) { }

    // ════════════════════════════════════════════════════════════════════════
    // AUTO-INTERACTION — fire events on key elements
    // ════════════════════════════════════════════════════════════════════════
    // Spustí se ze strany Pythonu po grace period; tady jen export funkce.
    // Deep query: match `sel` in the light DOM AND recursively inside every
    // OPEN shadow root (Web Components / custom elements). document.query-
    // SelectorAll stops at shadow boundaries, so without this the auto-inter-
    // action never touched inputs/buttons/forms inside components — DOM XSS that
    // needs interacting with a shadow-DOM element was silently missed. Closed
    // shadow roots are inaccessible from JS (browser limitation, not ours).
    function __xssgDeepQueryAll(sel, root) {
        root = root || document;
        var out = [];
        try {
            root.querySelectorAll(sel).forEach(function (e) { out.push(e); });
            root.querySelectorAll('*').forEach(function (e) {
                if (e.shadowRoot) {
                    __xssgDeepQueryAll(sel, e.shadowRoot).forEach(function (n) { out.push(n); });
                }
            });
        } catch (_) { }
        return out;
    }
    window.__xssgDeepQueryAll = __xssgDeepQueryAll;

    window.__xssg_auto_interact__ = function () {
        var count = 0;
        var MAX_INTERACT = 50;

        function tryEvent(el, type) {
            if (count >= MAX_INTERACT) return;
            try {
                var ev = new Event(type, { bubbles: true, cancelable: true });
                el.dispatchEvent(ev);
                count++;
            } catch (_) { }
        }

        // Click on links + buttons + custom-element hosts (může spustit onclick
        // handlery i interní logiku Web Components) — napříč shadow roots.
        try {
            var clickables = __xssgDeepQueryAll('a, button, [role=button], [onclick]');
            // Custom elements (tag s '-') často reagují na click vlastní logikou.
            __xssgDeepQueryAll('*').forEach(function (e) {
                try { if (e.tagName && e.tagName.indexOf('-') !== -1) clickables.push(e); } catch (_) { }
            });
            for (var i = 0; i < clickables.length && count < MAX_INTERACT; i++) {
                tryEvent(clickables[i], 'click');
                tryEvent(clickables[i], 'mouseover');
            }
        } catch (_) { }

        // Focus on inputs (může spustit onfocus) — napříč shadow roots.
        try {
            var focusables = __xssgDeepQueryAll('input, textarea, select, [contenteditable]');
            for (var i = 0; i < focusables.length && count < MAX_INTERACT; i++) {
                tryEvent(focusables[i], 'focus');
                tryEvent(focusables[i], 'change');
                tryEvent(focusables[i], 'input');
            }
        } catch (_) { }

        // Submit forms — napříč shadow roots.
        try {
            var forms = __xssgDeepQueryAll('form');
            for (var i = 0; i < forms.length && count < MAX_INTERACT; i++) {
                try {
                    var subEv = new Event('submit', { bubbles: true, cancelable: true });
                    forms[i].dispatchEvent(subEv);
                    count++;
                } catch (_) { }
            }
        } catch (_) { }

        // Hash change event (Twitter-style #! XSS)
        try {
            window.dispatchEvent(new HashChangeEvent('hashchange'));
            count++;
        } catch (_) {
            try {
                var hev = document.createEvent('HashChangeEvent');
                hev.initEvent('hashchange', true, true);
                window.dispatchEvent(hev);
                count++;
            } catch (__) { }
        }

        S.interactions_done = count;
        return count;
    };

    // Backwards compat aliases (původní v5 hooks)
    window.__xss_detected__ = false;
    Object.defineProperty(window, '__xss_detected__', {
        get: function () { return S.triggered; },
        configurable: true
    });
    window.__dom_sinks__ = S.sink_hits;
    window.__csp_violations__ = S.csp_violations;
    window.__marker__ = MARKERS[0];

})();

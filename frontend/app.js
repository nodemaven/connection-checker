/* @author Salama Malek */
/*
 * Connection Checker.
 *
 * ICE gathering, candidate classification, the verdict matrix, ASN-based
 * family-mismatch resolution and TURN verification. Every non-obvious rule here
 * exists because of a real edge case seen in the wild (bracketed IPv6,
 * IPv4-mapped addresses, CGNAT ranges, dual-stack false leaks, allocation
 * teardown races) — tread carefully when changing the classification logic.
 */
(function () {
    'use strict';

    var apiBase = (window.NM_TOOLS_API && window.NM_TOOLS_API.base) || '/api';

    // i18n bridge — strings registered as __() in the widget PHP, localized
    // into this global; the hidden [data-i18n-key] DOM shim carries the
    // TranslatePress-translated values and wins when present.
    var STR = (typeof window !== 'undefined' && window.NM_CONNCHECK_STRINGS) || {};
    var DOM_STR = {};

    function stripTrpTags(v) {
        return v.replace(/<\/?trp-[a-z-]+(?:\s[^>]*)?>/gi, '');
    }

    function readI18nShim(root) {
        var nodes = (root || document).querySelectorAll('[data-i18n-shim] [data-i18n-key]');
        for (var i = 0; i < nodes.length; i++) {
            var key = nodes[i].getAttribute('data-i18n-key');
            var val = (nodes[i].textContent || '').replace(/\s+/g, ' ').trim();
            if (key && val) DOM_STR[key] = val;
        }
    }

    function s(path, fallback) {
        if (Object.prototype.hasOwnProperty.call(DOM_STR, path)) {
            var dom = stripTrpTags(DOM_STR[path]).trim();
            if (dom) return dom;
        }
        var keys = path.split('.');
        var cur = STR;
        for (var i = 0; i < keys.length; i++) {
            if (cur && typeof cur === 'object') cur = cur[keys[i]];
            else return fallback;
        }
        if (typeof cur !== 'string' || !cur) return fallback;
        return stripTrpTags(cur) || fallback;
    }

    function setText(root, selector, value) {
        var node = root.querySelector(selector);
        if (node) node.textContent = value == null ? '' : String(value);
    }

    function setFieldValue(root, ddSelector, value, state) {
        var dd = root.querySelector(ddSelector);
        if (!dd) return;
        var span = dd.querySelector('.nm-fields__value');
        if (span) span.textContent = value == null ? '' : String(value);
        else dd.textContent = value == null ? '' : String(value);
        if (state) dd.setAttribute('data-state', state);
    }

    function classifyFamily(ip) {
        if (!ip) return 'unknown';
        return ip.indexOf(':') >= 0 ? 'ipv6' : 'ipv4';
    }

    // Canonicalise every address at ingestion: strip URL-style [brackets],
    // unwrap IPv4-mapped IPv6 (::ffff:1.2.3.4 must compare equal to the bare
    // HTTP IPv4), strip IPv6 zone ids. Without this a same-address case reads
    // as a leak (webrtc widget bug-log §3).
    function normalizeAddress(addr) {
        if (!addr) return addr;
        addr = String(addr).trim();
        if (addr.charAt(0) === '[') {
            var end = addr.lastIndexOf(']');
            if (end > 0) addr = addr.slice(1, end);
        }
        var mapped = addr.toLowerCase().match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
        if (mapped) return mapped[1];
        var pct = addr.indexOf('%');
        if (pct > 0 && addr.indexOf(':') >= 0) addr = addr.slice(0, pct);
        return addr;
    }

    // Expand an IPv6 string to a 16-byte array. Handles "::" shorthand.
    function toIpv6Bytes(ip) {
        if (!ip) return null;
        ip = normalizeAddress(ip);
        if (ip.indexOf(':') < 0) return null;
        var parts = ip.toLowerCase().split('::');
        if (parts.length > 2) return null;
        var left  = parts[0] ? parts[0].split(':') : [];
        var right = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
        var tail = right.length ? right[right.length - 1] : '';
        if (tail.indexOf('.') >= 0) return null;
        var fill = 8 - left.length - right.length;
        if (fill < 0 || (parts.length === 1 && fill !== 0)) return null;
        var hextets = left;
        for (var i = 0; i < fill; i++) hextets.push('0');
        hextets = hextets.concat(right);
        if (hextets.length !== 8) return null;
        var bytes = [];
        for (var j = 0; j < 8; j++) {
            var n = parseInt(hextets[j] || '0', 16);
            if (isNaN(n) || n < 0 || n > 0xffff) return null;
            bytes.push((n >> 8) & 0xff, n & 0xff);
        }
        return bytes;
    }

    // /64 is the canonical end-user IPv6 allocation; RFC 4941 privacy
    // extensions rotate the suffix inside it, so same-/64 is same network.
    function sameIpv6Prefix64(a, b) {
        var aB = toIpv6Bytes(a), bB = toIpv6Bytes(b);
        if (!aB || !bB) return false;
        for (var i = 0; i < 8; i++) if (aB[i] !== bB[i]) return false;
        return true;
    }

    // Addresses that must never be reported as a public leak: RFC 1918 +
    // RFC 6598 CGNAT (most mobile carriers — without it mobile srflx reads as
    // a public IP and false-flags a leak) + link-local + loopback, and the
    // IPv6 link-local / ULA / loopback / unspecified equivalents.
    function isLocalAddress(ip) {
        if (!ip) return false;
        if (ip.indexOf(':') >= 0) {
            var lower = ip.toLowerCase();
            if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;
            if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;
            if (lower === '::1' || lower === '::') return true;
            return false;
        }
        return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|127\.|169\.254\.|0\.0\.0\.0$)/.test(ip);
    }

    function dedupeCandidates(list) {
        var seen = {}, out = [];
        list.forEach(function (c) {
            var key = (c.address || '') + '|' + (c.type || '');
            if (!seen[key]) {
                seen[key] = true;
                out.push(c);
            }
        });
        return out;
    }

    // Fallback parser when event.candidate.type is not exposed (older browsers).
    function inferTypeFromCandidateString(str) {
        if (!str) return 'host';
        var m = str.match(/typ\s+(host|srflx|prflx|relay)/i);
        return m ? m[1].toLowerCase() : 'host';
    }

    function detectBrowser() {
        var ua = navigator.userAgent;
        var match;
        if ((match = ua.match(/Edg\/(\d+)/)))                        return 'Edge ' + match[1];
        if ((match = ua.match(/Firefox\/(\d+)/)))                    return 'Firefox ' + match[1];
        if (navigator.brave && navigator.brave.isBrave) {
            match = ua.match(/Chrome\/(\d+)/);
            return match ? 'Brave ' + match[1] : 'Brave';
        }
        if ((match = ua.match(/OPR\/(\d+)/)))                        return 'Opera ' + match[1];
        if ((match = ua.match(/Chrome\/(\d+)/)))                     return 'Chrome ' + match[1];
        if (/Safari\//.test(ua) && (match = ua.match(/Version\/(\d+)/))) return 'Safari ' + match[1];
        return 'Unknown';
    }

    function ConnectionChecker(root) {
        this.root = root;
        this.autoRun = root.getAttribute('data-auto-run') !== 'false';
        this.stunUrl = root.getAttribute('data-stun-url') || 'stun:stun.l.google.com:19302';
        this.turnCheck = root.getAttribute('data-turn-check') === 'true';
        this.h3Check = root.getAttribute('data-h3-check') === 'true';
        this.h3Base = (root.getAttribute('data-h3-base') || '').replace(/\/$/, '');
        this.activeConn = null;
        this.lastHttp = null;
        this.lastSrflxIp = null;
        // Per-channel observed addresses, aggregated into the "exposed
        // addresses" summary. Reset at the start of every run.
        this.httpExitIp = null;
        this.observedUdpIp = null;
        this.observedTcpIp = null;
        this.observedStunIp = null;
        // Monotonic run token: a Re-run while a previous gather is in flight
        // must not let stale resolutions overwrite the new run's UI.
        this.runToken = 0;
    }

    // Rebuild the "addresses your device exposed" summary from whatever each
    // channel has reported so far. Called incrementally as channels settle.
    // The HTTP exit is the visitor's intended identity; any OTHER distinct
    // public address a channel revealed is a real address that escaped the
    // proxy or anti-detect browser, and is highlighted as such.
    ConnectionChecker.prototype.refreshExposed = function () {
        var box = this.root.querySelector('[data-exposed-box]');
        var list = this.root.querySelector('[data-exposed-list]');
        if (!box || !list) return;

        var http = this.httpExitIp;
        // label -> ip, in priority order; nulls and private/local addresses
        // dropped. HTTP/3 is NOT listed here: it is a supported-or-not check,
        // not an address to compare (per product review — the QUIC probe can
        // report a private relay hop like 172.22.0.1, which is never a real
        // exposure).
        var channels = [
            ['http', s('exposed.http', 'HTTP (your exit)'), http],
            ['webrtc', s('exposed.webrtc', 'WebRTC (browser-reported)'), this.lastSrflxIp],
            ['stun', s('exposed.stun', 'WebRTC STUN source (server-observed)'), this.observedStunIp],
            ['turnUdp', s('exposed.turnUdp', 'WebRTC relay (UDP, server-observed)'), this.observedUdpIp],
            ['turnTcp', s('exposed.turnTcp', 'WebRTC relay (TCP, server-observed)'), this.observedTcpIp]
        ];

        var rows = [];
        var leakedIps = {};
        var seenIp = {};
        for (var i = 0; i < channels.length; i++) {
            var key = channels[i][0], label = channels[i][1], ip = channels[i][2];
            // Private / loopback / link-local addresses are never a public
            // exposure — a LAN or container IP does not identify the device to
            // a remote site, so it must not flip the verdict to "leak".
            if (!ip || isLocalAddress(ip)) continue;
            var leaked = key !== 'http' && !!http && ip !== http;
            if (leaked) leakedIps[ip] = true;
            rows.push({ label: label, ip: ip, leaked: leaked });
            seenIp[ip] = true;
        }
        if (rows.length === 0) return;

        // Render rows.
        list.innerHTML = '';
        for (var j = 0; j < rows.length; j++) {
            var row = document.createElement('div');
            row.className = 'nm-exposed__row' + (rows[j].leaked ? ' is-leaked' : '');
            var l = document.createElement('span');
            l.className = 'nm-exposed__label';
            l.textContent = rows[j].label;
            var v = document.createElement('b');
            v.className = 'nm-exposed__ip';
            v.textContent = rows[j].ip;
            row.appendChild(l);
            row.appendChild(v);
            list.appendChild(row);
        }

        var leakedCount = 0;
        for (var ip2 in leakedIps) { if (leakedIps.hasOwnProperty(ip2)) leakedCount++; }
        if (leakedCount > 0) {
            box.setAttribute('data-tone', 'bad');
            setText(this.root, '[data-exposed-title]', s('exposed.leakTitle', 'Your device exposed a real address'));
            setText(this.root, '[data-exposed-copy]', s('exposed.leakCopy', 'One or more channels revealed an address different from your HTTP exit. That address escaped your proxy or anti-detect browser and is visible to sites that probe these channels.'));
        } else if (this.webrtcBlocked) {
            // No address leaked, but WebRTC is blocked — a real user's HTTP IP
            // matches an observable WebRTC address, so this is a detectability
            // signal, not a clean pass. Amber (a warning), not red: it is less
            // severe than a real leaked address, and it keeps the headline
            // consistent with the WebRTC check verdict below instead of a
            // misleading green.
            box.setAttribute('data-tone', 'warning');
            setText(this.root, '[data-exposed-title]', s('exposed.blockedTitle', 'WebRTC blocked — your connection looks inconsistent'));
            setText(this.root, '[data-exposed-copy]', s('exposed.blockedCopy', 'No separate address leaked, but WebRTC returned nothing. A real user’s public HTTP IP matches their WebRTC STUN/TURN address, so a fully blocked WebRTC is itself a detectability signal that anti-bot systems flag. See the WebRTC check below.'));
        } else {
            box.setAttribute('data-tone', 'good');
            setText(this.root, '[data-exposed-title]', s('exposed.cleanTitle', 'No separate address exposed'));
            setText(this.root, '[data-exposed-copy]', s('exposed.cleanCopy', 'Every channel we could observe showed the same address as your HTTP exit. Nothing leaked a second identity on this setup.'));
        }
        box.removeAttribute('hidden');
    };

    ConnectionChecker.prototype.init = function () {
        var self = this;

        readI18nShim(this.root);

        setText(this.root, '[data-browser]', detectBrowser());

        var rerun = this.root.querySelector('[data-rerun]');
        if (rerun) {
            rerun.addEventListener('click', function () { self.run(); });
        }

        var download = this.root.querySelector('[data-download-report]');
        if (download) {
            download.addEventListener('click', function () { self.downloadReport(); });
        }

        var toggle = this.root.querySelector('[data-report-toggle]');
        if (toggle) {
            toggle.addEventListener('click', function () { self.toggleReport(); });
        }

        var copy = this.root.querySelector('[data-report-copy]');
        if (copy) {
            copy.addEventListener('click', function () { self.copyReport(); });
        }

        if (this.autoRun) {
            this.run();
        }
    };

    // While any check is in flight the report is incomplete, so lock every
    // control: no second run, and no view / copy / download of pending data.
    // Unlocked again only once ALL checks (STUN, TURN, HTTP/3) have finished.
    ConnectionChecker.prototype.setBusy = function (busy) {
        var ids = ['[data-rerun]', '[data-download-report]', '[data-report-toggle]', '[data-report-copy]'];
        for (var i = 0; i < ids.length; i++) {
            var el = this.root.querySelector(ids[i]);
            if (el) { el.disabled = !!busy; el.setAttribute('aria-disabled', busy ? 'true' : 'false'); }
        }
        this.root.classList.toggle('nm-conncheck--busy', !!busy);
        // A fresh run invalidates any open report; close it so no stale or
        // partial data stays on screen while the controls are locked.
        if (busy) {
            var term = this.root.querySelector('[data-report-terminal]');
            if (term && !term.hasAttribute('hidden')) {
                term.setAttribute('hidden', '');
                var tb = this.root.querySelector('[data-report-toggle]');
                if (tb) tb.setAttribute('aria-expanded', 'false');
                setText(this.root, '[data-report-toggle-label]', s('report.view', 'View report data'));
            }
        }
    };

    ConnectionChecker.prototype.run = function () {
        var self = this;
        if (this.activeConn) {
            try { this.activeConn.close(); } catch (e) { /* */ }
            this.activeConn = null;
        }
        var myToken = ++this.runToken;
        this.setBusy(true);
        function ifCurrent(fn) {
            return function (arg) { if (self.runToken === myToken) fn(arg); };
        }

        this.resetResults();
        this.setStatus('running');
        this.setVerdict('running',
            s('verdict.runningTitle', 'Running test…'),
            s('verdict.runningCopy', 'Collecting ICE candidates from your browser.'));

        // TURN credentials must exist before the RTCPeerConnection is built —
        // iceServers is constructor-time config. Fetch alongside the HTTP IP;
        // a failed mint degrades to STUN-only (turnCreds === null).
        Promise.all([
            this.fetchExitIp(),
            this.turnCheck ? this.fetchTurnCredentials() : Promise.resolve(null),
        ]).then(function (results) {
            if (self.runToken !== myToken) return null;
            var httpData = results[0];
            var turnCreds = results[1];
            self.populateExitIp(httpData);
            setText(self.root, '[data-browser]', detectBrowser());
            return self.collectCandidates(turnCreds).then(function (candidates) {
                return { candidates: candidates, turnCreds: turnCreds };
            });
        }).then(ifCurrent(function (result) {
            if (!result || !result.candidates) return null;
            self.populateCandidatePanel(result.candidates);
            self.computeVerdict(result.candidates);
            self.setStatus('complete');
            // The STUN verdict is in, but TURN and HTTP/3 are still pending —
            // keep the controls locked until those resolve too, so the report
            // can never be viewed or downloaded half-finished.
            var tail = [];
            if (self.turnCheck) tail.push(self.runTurnCheck(result.turnCreds));
            if (self.h3Check) tail.push(self.runH3Check());
            return Promise.all(tail);
        })).then(ifCurrent(function () {
            self.setBusy(false);
        })).catch(ifCurrent(function (error) {
            self.setStatus('error');
            self.setVerdict('warning',
                s('verdict.testFailedTitle', 'Test failed'),
                (error && error.message) || s('verdict.unknownError', 'Unknown error.'));
            self.setBusy(false);
        }));
    };

    ConnectionChecker.prototype.fetchExitIp = function () {
        var self = this;
        // Cache-buster + no-store: the response is caller-specific. Each
        // attempt is bounded by a 7s abort so a stalled endpoint degrades
        // instead of pinning the run — and one automatic retry, because the
        // tool's own audience sits behind proxies and the first request
        // through a cold residential tunnel routinely blows the first 7s
        // (seen live: first load "Verdict unavailable", re-run clean).
        function attempt() {
            var url = apiBase + '/ip?_t=' + Date.now();
            var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
            var timer = controller ? setTimeout(function () { controller.abort(); }, 7000) : null;
            var opts = {
                cache: 'no-store',
                headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' },
            };
            if (controller) opts.signal = controller.signal;
            return fetch(url, opts).then(function (response) {
                if (timer) clearTimeout(timer);
                if (!response.ok) throw new Error('ip endpoint returned ' + response.status);
                return response.json();
            }).catch(function () {
                if (timer) clearTimeout(timer);
                return null;
            });
        }

        // Resolve the exit over IPv4 by default. The WP /ip host is dual-stack,
        // so a browser on a dual-stack line often reaches it over IPv6 — but
        // every WebRTC channel we observe is IPv4 (the relay/STUN servers are
        // v4-only), so a v6 exit would never match a v4 WebRTC address and the
        // summary would flag a false leak (reported on a Thai dual-stack line:
        // HTTP v6 2405:… vs WebRTC v4 27.130.…, same network, wrongly red).
        // The research host has no AAAA record, so fetching it forces the v4
        // source; we then enrich that v4 with the WP lookup for ISP / ASN.
        function forcedV4Once() {
            if (!self.h3Base) return Promise.resolve(null);
            var url = self.h3Base + '/ip?_t=' + Date.now();
            var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
            // 8s, not 6s: a cold residential-proxy tunnel inside an anti-detect
            // browser routinely takes longer than 6s on the first hit, and a
            // timeout here drops us to the dual-stack WP endpoint, which returns
            // the client's IPv6 — reintroducing the exact family-mismatch this
            // v4-forcing exists to prevent (reported live: proxy exit shown as a
            // leak against a leaked IPv6 baseline).
            var timer = controller ? setTimeout(function () { controller.abort(); }, 8000) : null;
            var opts = { cache: 'no-store', mode: 'cors' };
            if (controller) opts.signal = controller.signal;
            return fetch(url, opts).then(function (r) {
                if (timer) clearTimeout(timer);
                return r.ok ? r.json() : null;
            }).then(function (d) {
                // IPv4, and PUBLIC only. Once the browser has learned the
                // research host speaks h3, a re-run can fetch /ip over QUIC,
                // where the edge reports a private relay hop (172.22.0.1)
                // instead of the client — that must never become the exit, so
                // reject it and let the WP /ip fallback below take over.
                if (d && d.ip && d.ip.indexOf(':') < 0 && !isLocalAddress(d.ip)) return d.ip;
                return null;
            }).catch(function () {
                if (timer) clearTimeout(timer);
                return null;
            });
        }
        // One automatic retry, same reason the WP /ip fetch retries: the exit
        // baseline must be the v4 proxy address, so it is worth a second attempt
        // before conceding to the dual-stack fallback.
        function forcedV4() {
            return forcedV4Once().then(function (v4) { return v4 || forcedV4Once(); });
        }
        function enrich(v4) {
            return fetch(apiBase + '/ip/' + encodeURIComponent(v4) + '?_t=' + Date.now(), { cache: 'no-store' })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (rich) { return (rich && rich.ip) ? rich : { ip: v4 }; })
                .catch(function () { return { ip: v4 }; });
        }

        self.diag = self.diag || {};
        return forcedV4().then(function (v4) {
            self.diag.forcedIpv4Result = v4 || null;
            if (v4) { self.diag.exitResolvedVia = 'forced-ipv4'; return enrich(v4); }
            // No IPv4 path (v6-only client, or research host unreachable):
            // fall back to whatever the WP endpoint returns. Recorded so a
            // downloaded report shows at a glance whether the exit came from the
            // forced-v4 path or the dual-stack fallback.
            self.diag.exitResolvedVia = 'wp-fallback';
            return attempt().then(function (data) { return data || attempt(); });
        });
    };

    // Mints a short-lived TURN-REST credential. Returns null on any failure so
    // the caller silently falls back to STUN-only — the TURN check is additive.
    ConnectionChecker.prototype.fetchTurnCredentials = function () {
        return fetch(apiBase + '/webrtc/turn-credentials', { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .catch(function () { return null; });
    };

    ConnectionChecker.prototype.populateExitIp = function (data) {
        if (!data || !data.ip) {
            setText(this.root, '[data-exit-ip]', s('ip.unavailable', 'Unavailable'));
            setText(this.root, '[data-exit-isp]', '—');
            setText(this.root, '[data-exit-location]', '—');
            setText(this.root, '[data-exit-asn]', '—');
            this.lastHttp = null;
            return;
        }
        setText(this.root, '[data-exit-ip]', data.ip);
        setText(this.root, '[data-exit-isp]', data.isp || '—');
        var loc = [data.country && data.country.name, data.city].filter(Boolean).join(', ');
        setText(this.root, '[data-exit-location]', loc || '—');
        var asn = data.asn && data.asn.number
            ? 'AS' + data.asn.number + (data.asn.name ? ' ' + data.asn.name : '')
            : '—';
        setText(this.root, '[data-exit-asn]', asn);
        this.lastHttp = {
            ip: data.ip,
            family: data.ip.indexOf(':') >= 0 ? 'ipv6' : 'ipv4',
            asn: (data.asn && data.asn.number) || null,
        };
        this.httpExitIp = normalizeAddress(data.ip);
        this.refreshExposed();
    };

    // Collect ICE candidates from the structured event.candidate properties —
    // not by regex-sweeping the SDP. The srflx candidate's address is the
    // public IP that matters for leak detection.
    ConnectionChecker.prototype.collectCandidates = function (turnCreds) {
        var self = this;
        return new Promise(function (resolve) {
            if (!window.RTCPeerConnection) {
                resolve({ supported: false, candidates: [] });
                return;
            }

            var iceServers = [{ urls: self.stunUrl }];
            // A TURN entry makes the browser attempt a real relay allocation as
            // part of normal ICE gathering — that allocation is what the
            // server-side readback observes.
            if (turnCreds && turnCreds.urls) {
                iceServers.push({
                    urls: turnCreds.urls,
                    username: turnCreds.username,
                    credential: turnCreds.credential,
                });
            }
            // Second TURN entry over TCP. An anti-detect browser that blocks
            // WebRTC-over-UDP can still be caught here if it lets the TCP relay
            // go direct — coturn then observes its real address on the TCP leg.
            // Keyed by a separate "-tcp" username so the readback reports it
            // independently of the UDP observation.
            if (turnCreds && turnCreds.tcp && turnCreds.tcp.urls) {
                iceServers.push({
                    urls: turnCreds.tcp.urls,
                    username: turnCreds.tcp.username,
                    credential: turnCreds.tcp.credential,
                });
            }
            // Our own per-session STUN server. srflx gathering sends a plain
            // Binding request here from the real UDP source, which our server
            // records under this session's token — catching the address even
            // when the browser spoofs the srflx it reports and blocks the TURN
            // allocation. The port is the session key.
            if (turnCreds && turnCreds.stun && turnCreds.stun.url) {
                iceServers.push({ urls: turnCreds.stun.url });
            }

            var pc;
            try {
                pc = new RTCPeerConnection({ iceServers: iceServers });
            } catch (e) {
                resolve({ supported: false, candidates: [] });
                return;
            }

            self.activeConn = pc;

            try {
                pc.createDataChannel('nm-conncheck-test');
            } catch (e) { /* some browsers — ignore */ }

            var done = false;
            var collected = [];

            pc.onicecandidate = function (event) {
                if (event.candidate) {
                    var c = event.candidate;
                    if (c.candidate && c.address) {
                        collected.push({
                            address: normalizeAddress(c.address),
                            type: c.type || inferTypeFromCandidateString(c.candidate),
                            protocol: c.protocol || 'udp',
                        });
                    }
                } else if (!done) {
                    finish();
                }
            };

            pc.onicegatheringstatechange = function () {
                if (pc.iceGatheringState === 'complete' && !done) {
                    finish();
                }
            };

            pc.createOffer().then(function (offer) {
                return pc.setLocalDescription(offer);
            }).catch(function () {
                if (!done) {
                    finish();
                }
            });

            // 5s hard cap — Safari rarely fires iceGatheringState=complete.
            setTimeout(function () {
                if (!done) {
                    finish();
                }
            }, 5000);

            function finish() {
                done = true;
                // Closing the peer connection tears down its TURN allocation
                // immediately, and the readback needs the coturn record to
                // still exist when it queries ~1.5s later. With a TURN
                // credential in play, delay the close past that window; plain
                // STUN-only runs close immediately.
                if (turnCreds) {
                    setTimeout(function () {
                        try { pc.close(); } catch (e) { /* */ }
                        if (self.activeConn === pc) self.activeConn = null;
                    }, 4000);
                } else {
                    try { pc.close(); } catch (e) { /* */ }
                    self.activeConn = null;
                }
                resolve({
                    supported: true,
                    candidates: dedupeCandidates(collected),
                });
            }
        });
    };

    ConnectionChecker.prototype.populateCandidatePanel = function (data) {
        var srflxV4 = [], srflxV6 = [], localIps = [], mdns = [];
        (data.candidates || []).forEach(function (c) {
            var addr = c.address || '';
            if (!addr) return;
            if (/\.local(:\d+)?$/i.test(addr)) {
                if (mdns.indexOf(addr) < 0) mdns.push(addr);
                return;
            }
            var family = classifyFamily(addr);
            var loc = isLocalAddress(addr);
            if (c.type === 'srflx' || c.type === 'prflx') {
                if (family === 'ipv4' && srflxV4.indexOf(addr) < 0) srflxV4.push(addr);
                else if (family === 'ipv6' && srflxV6.indexOf(addr) < 0) srflxV6.push(addr);
            } else if (c.type === 'host' && loc) {
                if (localIps.indexOf(addr) < 0) localIps.push(addr);
            }
        });

        var none = s('tiles.none', 'None');
        setText(this.root, '[data-webrtc-public]', srflxV4.join(', ')  || none);
        setText(this.root, '[data-webrtc-ipv6]',   srflxV6.join(', ')  || none);
        setText(this.root, '[data-webrtc-local]',  localIps.join(', ') || none);
        setText(this.root, '[data-webrtc-mdns]',   mdns.slice(0, 3).join(', ') || none);

        // What the TURN check compares against — prefer v4 (the TURN
        // allocation is UDP/IPv4-only per turnserver.conf).
        this.lastSrflxIp = srflxV4[0] || srflxV6[0] || null;
        // Kept for the downloadable report.
        this.reportCandidates = { srflxV4: srflxV4, srflxV6: srflxV6, localIps: localIps, mdns: mdns };
        this.rawCandidates = data.candidates || [];
        this.refreshExposed();
    };

    // Verdict matrix, ported unchanged:
    //   srflx ≠ HTTP exit IP                  → Leak detected (bad)
    //   srflx = HTTP exit IP                  → No leak detected (good)
    //   only mDNS / no srflx                  → No leak detected (good)
    //   raw LAN IP visible                    → Leak + privacy regression (bad)
    //   HTTP fetch failed                     → Verdict unavailable (warning)
    //   no RTCPeerConnection                  → No leak possible (good)
    //   cross-family srflx                    → ASN decides (resolveFamilyMismatch)
    ConnectionChecker.prototype.computeVerdict = function (data) {
        if (!data.supported) {
            this.setVerdict('good',
                s('verdict.noApiTitle', 'No leak possible'),
                s('verdict.noApiCopy', 'WebRTC is not available in this browser session, so there is no API to leak through.'));
            return;
        }

        var srflx = [], hostPrivate = [];
        (data.candidates || []).forEach(function (c) {
            var addr = c.address || '';
            if (!addr || /\.local(:\d+)?$/i.test(addr)) return;
            if (c.type === 'srflx' || c.type === 'prflx') {
                srflx.push({ address: addr, family: classifyFamily(addr) });
            } else if (c.type === 'host' && isLocalAddress(addr)) {
                hostPrivate.push(addr);
            }
        });

        if (srflx.length === 0 && hostPrivate.length === 0) {
            // No WebRTC address reached page JavaScript. This is NOT a clean
            // pass: a real user's public HTTP IP matches their WebRTC STUN/TURN
            // address, so a fully blocked WebRTC is itself a detectability red
            // flag — cheap anti-detect tools and some extensions just drop the
            // STUN/TURN requests, and anti-bot systems treat the missing WebRTC
            // as an inconsistency. Marked blocked so the TURN readback can still
            // upgrade this to a server-verified leak if our relay DID observe a
            // real address (the browser hid it but the UDP still escaped).
            this.webrtcBlocked = true;
            // Amber, not red: a blocked WebRTC is a real detectability signal,
            // but it is less severe than an exposed address (a real leak), and
            // many privacy-conscious real users block WebRTC too. Red is
            // reserved for an actual leaked address.
            this.setVerdict('warning',
                s('verdict.blockedTitle', 'WebRTC blocked — consistency signal'),
                s('verdict.blockedCopy', 'No WebRTC address reached the page. A real user’s public HTTP IP matches their WebRTC STUN/TURN address, so a fully blocked WebRTC is itself a detectability signal — anti-bot systems read the missing WebRTC as an inconsistency. Cheap anti-detect tools and some browser extensions cause exactly this by dropping STUN/TURN requests. It is less exposing than a real leak, but it makes you stand out from a default browser.'));
            this.setVerdictCompare(this.lastHttp && this.lastHttp.ip, s('compare.blocked', 'Blocked / none'));
            // Reflect the block in the summary headline immediately (also covers
            // the case where the TURN check is off and never re-runs it).
            this.refreshExposed();
            return;
        }

        if (hostPrivate.length > 0) {
            this.setVerdict('bad',
                s('verdict.privacyRegTitle', 'Leak + privacy regression'),
                s('verdict.privacyRegCopy', 'WebRTC exposed a raw LAN address. mDNS obfuscation is disabled. Re-enable browser default privacy settings.'));
            this.setVerdictCompare(this.lastHttp && this.lastHttp.ip, hostPrivate[0]);
            return;
        }

        if (!this.lastHttp) {
            this.setVerdict('warning',
                s('verdict.unavailableTitle', 'Verdict unavailable'),
                s('verdict.unavailableCopy', 'WebRTC exposed a public IP, but your HTTP exit IP could not be fetched to compare.'));
            this.setVerdictCompare(s('compare.unavailable', 'Unavailable'), srflx[0] && srflx[0].address);
            return;
        }

        // Per-family comparison: exact match for IPv4, /64 prefix for IPv6
        // (privacy extensions rotate the suffix within the allocation).
        var httpIp = this.lastHttp.ip;
        var httpFamily = this.lastHttp.family;
        var sameFamily = srflx.filter(function (c) { return c.family === httpFamily; });
        var leaking = sameFamily.filter(function (c) {
            if (httpFamily === 'ipv6') return !sameIpv6Prefix64(c.address, httpIp);
            return c.address !== httpIp;
        });

        if (sameFamily.length === 0) {
            // A cross-family address is only a second identity when the two
            // networks differ — a dual-stack home line hits this branch too.
            this.resolveFamilyMismatch(httpIp, srflx[0].address);
            return;
        }
        if (leaking.length > 0) {
            this.setVerdict('bad',
                s('verdict.leakTitle', 'Leak detected'),
                s('verdict.leakCopy', 'WebRTC exposed an IP that does not match the HTTP exit IP. Disable or constrain WebRTC before trusting this browser profile.'));
            this.setVerdictCompare(httpIp, leaking[0].address);
            return;
        }
        this.setVerdict('good',
            s('verdict.noLeakMatchTitle', 'No leak detected'),
            s('verdict.noLeakMatchCopy', 'WebRTC and your HTTP exit IP take the same path. No separate identity is exposed.'));
        this.setVerdictCompare(httpIp, sameFamily[0].address);
    };

    // Decide whether a cross-family address is a genuine second identity by
    // comparing the two networks (ASN), not the two IP versions. Errs toward
    // "leak" when the ASN cannot be resolved: a false alarm makes someone
    // check their setup, a false all-clear makes them trust an exposed profile.
    ConnectionChecker.prototype.resolveFamilyMismatch = function (httpIp, webrtcIp) {
        var self = this;
        var httpAsn = this.lastHttp && this.lastHttp.asn;
        var myToken = this.runToken;

        this.setVerdictCompare(httpIp, webrtcIp);

        var render = function (sameNetwork) {
            if (self.runToken !== myToken) return;
            if (sameNetwork) {
                self.setVerdict('warning',
                    s('verdict.sameNetworkTitle', 'No separate identity exposed'),
                    s('verdict.sameNetworkCopy', 'WebRTC used a different IP version than your HTTP connection, but both addresses belong to the same network, so this is one connection reachable over IPv4 and IPv6 rather than a second identity. If you expected a proxy or VPN to be active here, it is not covering this traffic.'));
                return;
            }
            self.setVerdict('bad',
                s('verdict.incompleteProxyTitle', 'Leak detected on a different IP family'),
                s('verdict.incompleteProxyCopy', 'WebRTC exposed a public IP on a different IP family and a different network from your HTTP exit IP, so it did not travel through the same proxy or VPN. It is a separate identity, visible to every site you open.'));
        };

        if (!httpAsn) {
            render(false);
            return;
        }

        fetch(apiBase + '/ip/' + encodeURIComponent(webrtcIp), { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                var webrtcAsn = data && data.asn && data.asn.number;
                render(!!webrtcAsn && webrtcAsn === httpAsn);
            })
            .catch(function () { render(false); });
    };

    // Read back one channel's server-observed address. Resolves to the IP
    // string coturn saw for that username, or null if nothing was observed.
    ConnectionChecker.prototype.fetchObserved = function (username) {
        if (!username) return Promise.resolve(null);
        var url = apiBase + '/webrtc/turn-observed?username=' + encodeURIComponent(username);
        return fetch(url, { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                return (data && data.found && data.ip) ? normalizeAddress(data.ip) : null;
            })
            .catch(function () { return null; });
    };

    // Read back the source our STUN server observed for this session's token.
    ConnectionChecker.prototype.fetchStunObserved = function (token) {
        if (!token) return Promise.resolve(null);
        var url = apiBase + '/webrtc/stun-observed?token=' + encodeURIComponent(token);
        return fetch(url, { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                return (data && data.found && data.ip) ? normalizeAddress(data.ip) : null;
            })
            .catch(function () { return null; });
    };

    // Server-side comparison: what coturn actually observed for this session
    // vs what the browser told page JS via the srflx candidate. Now reads back
    // BOTH the UDP and TCP relay channels — a browser that hides its address on
    // one transport can still be caught on the other.
    ConnectionChecker.prototype.runTurnCheck = function (turnCreds) {
        var self = this;
        var box = this.root.querySelector('[data-turn-box]');
        if (!box) return Promise.resolve();
        var myToken = this.runToken;

        if (!turnCreds) {
            this.setTurnResult('warning',
                s('turn.unavailable', 'Unavailable'),
                s('turn.errorCopy', 'Could not complete the TURN check.'));
            return Promise.resolve();
        }

        this.setTurnResult('running', s('turn.checking', 'Checking…'), '');
        setText(this.root, '[data-turn-client-ip]', this.lastSrflxIp || '—');

        var tcpUsername = turnCreds.tcp && turnCreds.tcp.username;
        var stunToken = turnCreds.stun && turnCreds.stun.token;

        // The allocation write can lag the ICE candidate by a beat; wait
        // briefly so the readback does not race it. The returned promise
        // resolves when the whole check settles, so run() can keep the
        // controls locked until it does.
        return new Promise(function (turnDone) {
        setTimeout(function () {
            if (self.runToken !== myToken) { turnDone(); return; }
            Promise.all([
                self.fetchObserved(turnCreds.username),
                self.fetchObserved(tcpUsername),
                self.fetchStunObserved(stunToken),
            ]).then(function (results) {
                if (self.runToken !== myToken) return;
                var udpIp = results[0];
                var tcpIp = results[1];
                var stunIp = results[2];
                self.observedUdpIp = udpIp;
                self.observedTcpIp = tcpIp;
                self.observedStunIp = stunIp;

                setText(self.root, '[data-turn-observed-ip]', udpIp || '—');
                setText(self.root, '[data-turn-observed-tcp-ip]', tcpIp || s('turn.tcpNone', 'No TCP relay observed'));
                setText(self.root, '[data-turn-observed-stun-ip]', stunIp || '—');

                // The verdict keys on the strongest UDP-path observation we
                // have. The STUN source is the direct srflx-path address, so it
                // is the cleanest thing to compare the browser-reported srflx
                // against for spoofing; fall back to the TURN UDP allocation,
                // then the TCP relay, as those get blocked.
                var observed = stunIp || udpIp || tcpIp;
                if (!observed) {
                    if (!self.lastSrflxIp) {
                        // Nothing from the browser AND nothing at our relay:
                        // WebRTC is fully blocked. Per the consistency model this
                        // is a detectability red flag, not a clean pass — a real
                        // user's HTTP IP matches an observable WebRTC address.
                        self.setTurnResult('warning',
                            s('turn.noUdpTitle', 'TURN check: WebRTC blocked'),
                            s('turn.noUdpCopy', 'No UDP connection reached our relay and the browser exposed no WebRTC address, so WebRTC appears fully blocked. A real user’s public HTTP IP matches an observable WebRTC STUN/TURN address, so a blocked WebRTC is a detectability signal rather than a clean result.'));
                    } else {
                        self.setTurnResult('warning',
                            s('turn.unverifiedTitle', 'TURN check: could not verify'),
                            s('turn.unverifiedCopy', 'Your browser reported a public WebRTC address, but no connection carrying that address reached our server, so we could not confirm it. Either your network blocks the connection we use to check, or the browser is reporting an address it is not actually connecting from.'));
                    }
                } else {
                    var match = self.lastSrflxIp && observed === self.lastSrflxIp;
                    if (match) {
                        self.setTurnResult('good',
                            s('turn.matchTitle', 'TURN check: no spoofing detected'),
                            s('turn.matchCopy', 'The IP our server observed on the TURN relay matches the browser-reported WebRTC candidate.'));
                    } else {
                        self.setTurnResult('bad',
                            s('turn.mismatchTitle', 'TURN check: spoofing detected'),
                            s('turn.mismatchCopy', 'The IP our server observed on the TURN relay does not match the browser-reported WebRTC candidate. This browser is altering its WebRTC address before it reaches page JavaScript.'));
                    }
                }

                // Reconcile the main STUN leak card with what the SERVER saw.
                // When an anti-detect browser masks the srflx it reports to
                // match the HTTP exit, computeVerdict (which trusts that report)
                // shows a false "No leak detected". The server-observed source
                // cannot be masked, so if it differs from the HTTP exit, WebRTC
                // is exposing a hidden identity — upgrade the card to a leak.
                var serverSrc = self.observedStunIp || self.observedUdpIp;
                if (serverSrc && self.httpExitIp && serverSrc !== self.httpExitIp) {
                    var verdictBox = self.root.querySelector('[data-verdict-box]');
                    // Upgrade to a server-verified leak from any non-leak state,
                    // INCLUDING the "WebRTC blocked" consistency flag: if our
                    // relay caught a real address, the browser only *looked*
                    // blocked to the page while its UDP still escaped — that is a
                    // leak, which is worse than an inconsistency.
                    if (verdictBox && (verdictBox.getAttribute('data-tone') !== 'bad' || self.webrtcBlocked)) {
                        self.setVerdict('bad',
                            s('verdict.maskedLeakTitle', 'Leak detected (server-verified)'),
                            s('verdict.maskedLeakCopy', 'Your browser reported an address matching your HTTP exit, but our server observed a different real address over UDP. WebRTC is exposing an identity your browser tried to hide.'));
                        self.setVerdictCompare(self.httpExitIp, serverSrc);
                    }
                }
                self.refreshExposed();
            }).catch(function () { /* the check is best-effort; never block the UI */ })
              .then(function () { turnDone(); });
        }, 1500);
        });
    };

    // HTTP/3 check: two sequential fetches against the probe origin. The
    // first response teaches the browser the origin speaks h3 (Alt-Svc,
    // added by the server); the second may then travel over QUIC. The only
    // honest source for what actually happened is the second fetch's
    // Resource Timing entry — the server cannot know, and the page cannot
    // read the entry cross-origin unless the probe sends Timing-Allow-Origin.
    ConnectionChecker.prototype.runH3Check = function () {
        var self = this;
        var box = this.root.querySelector('[data-h3-box]');
        if (!box || !this.h3Base) return Promise.resolve();
        var myToken = this.runToken;

        this.setH3Result('running', s('h3.checking', 'Checking…'), '');

        function probe(n) {
            var url = self.h3Base + '/h3probe?n=' + n + '&_t=' + Date.now();
            var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
            // First attempt gets a cold-tunnel allowance; the connection is warm
            // after that, so later attempts fail faster instead of hanging 7s each.
            var timer = controller ? setTimeout(function () { controller.abort(); }, n === 1 ? 7000 : 4000) : null;
            var opts = { cache: 'no-store', mode: 'cors' };
            if (controller) opts.signal = controller.signal;
            return fetch(url, opts).then(function (r) {
                if (timer) clearTimeout(timer);
                if (!r.ok) throw new Error('probe ' + r.status);
                // The body MUST be consumed: the browser only queues the
                // Resource Timing entry once the response is fully read, so
                // an unread body means getEntriesByName finds nothing and
                // the check dead-ends at "could not measure".
                return r.text().then(function () { return { url: url }; });
            }).catch(function (e) {
                if (timer) clearTimeout(timer);
                throw e;
            });
        }

        // The first response teaches the browser the origin speaks h3, but
        // the browser keeps riding its warm TCP connection while the raced
        // QUIC connection establishes — measured live on staging: attempts
        // 1-2 report h2, attempt 3 onward report h3. So the question "can
        // this connection negotiate QUIC at all" needs several attempts:
        // h3 on ANY attempt is a pass, all-TCP after MAX_ATTEMPTS is a
        // genuine fallback.
        var MAX_ATTEMPTS = 5;
        // Total time budget. A connection that CAN do h3 is fast, so all five
        // attempts finish well inside this and h3 (which only shows from ~attempt
        // 3) is caught. A connection that can't carry UDP — e.g. a proxy, exactly
        // this tool's audience — is both slow AND never h3, so once the budget is
        // spent we conclude with the TCP fallback we already saw instead of
        // grinding through all five and leaving "Checking…" on screen for ~35s.
        var H3_BUDGET_MS = 12000;
        var startedAt = Date.now();
        var lastTcpProto = '';

        function attempt(n) {
            // Live progress so a slow check never looks frozen.
            self.setH3Result('running', s('h3.checking', 'Checking…') + ' (' + n + '/' + MAX_ATTEMPTS + ')', '');
            return probe(n).then(function (res) {
                // The timing entry can land a beat after the fetch resolves.
                return new Promise(function (r) { setTimeout(function () { r(res); }, 450); });
            }).then(function (res) {
                var entries = performance.getEntriesByName(res.url);
                var proto = entries.length ? (entries[entries.length - 1].nextHopProtocol || '') : '';
                if (proto === 'h3') { return 'h3'; }
                if (proto === 'h2' || proto.indexOf('http/1') === 0) { lastTcpProto = proto; }
                if (n >= MAX_ATTEMPTS || (Date.now() - startedAt) > H3_BUDGET_MS) {
                    return lastTcpProto ? 'tcp' : 'unknown';
                }
                return attempt(n + 1);
            });
        }

        return attempt(1).then(function (outcome) {
            if (self.runToken !== myToken) return;
            // HTTP/3 is a support check only: did the connection negotiate QUIC
            // over UDP, or fall back to TCP. We deliberately do NOT compare the
            // QUIC-path source IP (per product review) — QUIC can arrive via a
            // private relay hop, and the WebRTC/TURN channels are the ones that
            // expose a real address.
            if (outcome === 'h3') {
                setText(self.root, '[data-h3-proto]', 'h3');
                self.setH3Result('good',
                    s('h3.h3Title', 'HTTP/3 works on your connection'),
                    s('h3.h3Copy', 'Your connection negotiated QUIC over UDP. Your traffic blends in with the large share of the web already using HTTP/3.'));
            } else if (outcome === 'tcp') {
                setText(self.root, '[data-h3-proto]', lastTcpProto);
                self.setH3Result('warning',
                    s('h3.fallbackTitle', 'Falling back to TCP'),
                    s('h3.fallbackCopy', 'Your connection could not negotiate QUIC and fell back to TCP. A connection that cannot carry UDP stands out next to the share of traffic already on HTTP/3. HTTP proxies and most SOCKS5 setups force exactly this fallback.'));
            } else {
                setText(self.root, '[data-h3-proto]', s('h3.unknownTitle', 'Could not measure'));
                self.setH3Result('warning',
                    s('h3.unknownTitle', 'Could not measure'),
                    s('h3.unknownCopy', 'We could not complete a QUIC handshake, so there is nothing to judge here, and this is not a detection. It usually means UDP is not available on this connection. That is expected on HTTP proxies and most SOCKS5 proxies, which do not carry UDP, and on networks that block QUIC. Re-run the check, and if it keeps happening the probe endpoint may be unreachable from your network.'));
            }
            self.refreshExposed();
        }).catch(function () {
            if (self.runToken !== myToken) return;
            // A failed fetch is NOT a TCP fallback — the endpoint may simply
            // be unreachable. Refusing to guess beats a wrong verdict.
            self.setH3Result('warning',
                s('h3.unknownTitle', 'Could not measure'),
                s('h3.unknownCopy', 'The probe did not return a readable result, so no verdict is possible. Re-run the check, and if this persists the probe endpoint may be unreachable from your network.'));
        });
    };

    ConnectionChecker.prototype.setH3Result = function (tone, title, copy) {
        var box = this.root.querySelector('[data-h3-box]');
        if (box) box.setAttribute('data-tone', tone);
        setText(this.root, '[data-h3-title]', title);
        setText(this.root, '[data-h3-copy]', copy);
    };

    ConnectionChecker.prototype.setVerdict = function (tone, title, copy) {
        var box = this.root.querySelector('[data-verdict-box]');
        if (box) box.setAttribute('data-tone', tone);
        setText(this.root, '[data-verdict-title]', title);
        setText(this.root, '[data-verdict-copy]', copy);
    };

    ConnectionChecker.prototype.setTurnResult = function (tone, title, copy) {
        var box = this.root.querySelector('[data-turn-box]');
        if (box) box.setAttribute('data-tone', tone);
        setText(this.root, '[data-turn-title]', title);
        setText(this.root, '[data-turn-copy]', copy);
    };

    ConnectionChecker.prototype.setVerdictCompare = function (httpIp, webrtcIp) {
        var block = this.root.querySelector('[data-verdict-compare]');
        if (!block) return;
        setText(this.root, '[data-verdict-http-ip]',   httpIp   || '—');
        setText(this.root, '[data-verdict-webrtc-ip]', webrtcIp || '—');
        block.removeAttribute('hidden');
    };

    // A full structured snapshot of the run — every rendered value plus the
    // internal diagnostics (how the exit was resolved, the raw ICE candidates,
    // the server-observed addresses). Shared as a file, this replaces
    // screenshot-by-screenshot debugging.
    ConnectionChecker.prototype.buildReport = function () {
        var root = this.root;
        function t(sel) { var e = root.querySelector(sel); return e ? e.textContent.replace(/\s+/g, ' ').trim() : null; }
        function tone(sel) { var e = root.querySelector(sel); return e ? e.getAttribute('data-tone') : null; }

        var channels = [];
        var listRows = root.querySelectorAll('[data-exposed-list] .nm-exposed__row');
        for (var i = 0; i < listRows.length; i++) {
            var lab = listRows[i].querySelector('.nm-exposed__label');
            var ipn = listRows[i].querySelector('.nm-exposed__ip');
            channels.push({
                label: lab ? lab.textContent.trim() : null,
                ip: ipn ? ipn.textContent.trim() : null,
                leaked: listRows[i].classList.contains('is-leaked'),
            });
        }

        var exitIp = t('[data-exit-ip]');
        var diag = this.diag || {};
        return {
            tool: 'connection-detectability-checker',
            generatedAt: new Date().toISOString(),
            page: { url: location.href, userAgent: navigator.userAgent, browser: t('[data-browser]') },
            config: {
                h3ProbeBase: this.h3Base || null,
                turnCheckEnabled: !!this.turnCheck,
                stunUrl: this.stunUrl || null,
                autoRun: !!this.autoRun,
            },
            exit: {
                ip: exitIp,
                family: exitIp ? (exitIp.indexOf(':') >= 0 ? 'ipv6' : 'ipv4') : null,
                isp: t('[data-exit-isp]'),
                location: t('[data-exit-location]'),
                asn: t('[data-exit-asn]'),
                checkStatus: t('[data-check-status]'),
                // The two fields that make a mislabelled run obvious at a glance.
                resolvedVia: diag.exitResolvedVia || null,
                forcedIpv4Result: diag.forcedIpv4Result || null,
            },
            http3: { verdict: t('[data-h3-title]'), tone: tone('[data-h3-box]'), negotiatedProtocol: t('[data-h3-proto]') },
            webrtcStun: {
                verdict: t('[data-verdict-title]'), tone: tone('[data-verdict-box]'),
                browserReportedPublicIp: t('[data-webrtc-public]'),
                publicIpv6: t('[data-webrtc-ipv6]'),
                localLanIp: t('[data-webrtc-local]'),
                mdns: t('[data-webrtc-mdns]'),
                verdictCompare: { httpIp: t('[data-verdict-http-ip]'), webrtcIp: t('[data-verdict-webrtc-ip]') },
            },
            turn: {
                verdict: t('[data-turn-title]'), tone: tone('[data-turn-box]'),
                browserReportedIp: t('[data-turn-client-ip]'),
                serverObservedStunSource: t('[data-turn-observed-stun-ip]'),
                serverObservedUdpRelay: t('[data-turn-observed-ip]'),
                serverObservedTcpRelay: t('[data-turn-observed-tcp-ip]'),
            },
            iceCandidates: this.reportCandidates || null,
            rawIceCandidates: this.rawCandidates || null,
            exposedSummary: { tone: tone('[data-exposed-box]'), verdict: t('[data-exposed-title]'), channels: channels },
            internalState: {
                httpExitIp: this.httpExitIp || null,
                lastSrflxIp: this.lastSrflxIp || null,
                observedStunIp: this.observedStunIp || null,
                observedUdpIp: this.observedUdpIp || null,
                observedTcpIp: this.observedTcpIp || null,
            },
        };
    };

    // Show/collapse the JSON inline. Rebuilds each time it is opened so it
    // always reflects the latest run.
    // Force the report terminal open and fill it with the current JSON.
    // Idempotent, so both the toggle and the download fallback can call it.
    ConnectionChecker.prototype.showReport = function () {
        var term = this.root.querySelector('[data-report-terminal]');
        var pre = this.root.querySelector('[data-report-json]');
        var btn = this.root.querySelector('[data-report-toggle]');
        if (!term || !pre) return;
        var json;
        try { json = JSON.stringify(this.buildReport(), null, 2); }
        catch (e) { json = '{ "error": "could not build report", "detail": ' + JSON.stringify(String(e)) + ' }'; }
        pre.textContent = json;
        term.removeAttribute('hidden');
        if (btn) {
            btn.setAttribute('aria-expanded', 'true');
            setText(this.root, '[data-report-toggle-label]', s('report.hide', 'Hide report data'));
        }
    };

    // Copy the report JSON to the clipboard from the terminal view. Uses the
    // async Clipboard API where available and falls back to a select + execCommand
    // range copy for browsers (or anti-detect ones) that withhold it.
    ConnectionChecker.prototype.copyReport = function () {
        var self = this;
        var pre = this.root.querySelector('[data-report-json]');
        var text = (pre && pre.textContent) || '';
        if (!text) {
            try { text = JSON.stringify(this.buildReport(), null, 2); }
            catch (e) { text = ''; }
        }
        var flash = function (ok) {
            setText(self.root, '[data-report-copy-label]',
                ok ? s('report.copied', 'Copied') : s('report.copy', 'Copy'));
            setTimeout(function () {
                setText(self.root, '[data-report-copy-label]', s('report.copy', 'Copy'));
            }, 1600);
        };
        var fallback = function () {
            try {
                if (!pre) { flash(false); return; }
                var range = document.createRange();
                range.selectNodeContents(pre);
                var sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
                var ok = document.execCommand('copy');
                sel.removeAllRanges();
                flash(!!ok);
            } catch (e) { flash(false); }
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () { flash(true); }, fallback);
        } else {
            fallback();
        }
    };

    ConnectionChecker.prototype.toggleReport = function () {
        var term = this.root.querySelector('[data-report-terminal]');
        var btn = this.root.querySelector('[data-report-toggle]');
        if (!term) return;
        if (term.hasAttribute('hidden')) { this.showReport(); return; }
        term.setAttribute('hidden', '');
        if (btn) {
            btn.setAttribute('aria-expanded', 'false');
            setText(this.root, '[data-report-toggle-label]', s('report.view', 'View report data'));
        }
    };

    ConnectionChecker.prototype.downloadReport = function () {
        var json;
        try { json = JSON.stringify(this.buildReport(), null, 2); }
        catch (e) { json = JSON.stringify({ error: 'could not build report', detail: String(e) }); }
        var name = 'connection-check-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';

        // Primary path: a blob download via a synthetic <a download> click.
        // Anti-detect and embedded browsers often block the blob: URL or the
        // programmatic click outright, so we only trust this path when the
        // anchor actually advertises download support, and we always keep a
        // fallback that still hands the visitor the data.
        var done = false;
        try {
            var a = document.createElement('a');
            if ('download' in a) {
                var blob = new Blob([json], { type: 'application/json' });
                var url = URL.createObjectURL(blob);
                a.href = url;
                a.download = name;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
                done = true;
            }
        } catch (e) { done = false; }

        if (done) return;

        // Fallback: reveal the JSON inline so it can be read and selected, and
        // copy it to the clipboard where the browser allows it. This is what
        // keeps the report retrievable inside anti-detect browsers that swallow
        // the download.
        this.showReport();
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(json);
            }
        } catch (e) { /* clipboard blocked; the inline panel is the fallback */ }
    };

    ConnectionChecker.prototype.setStatus = function (key) {
        var label, state;
        if (key === 'running') {
            label = s('status.running', 'Running');   state = 'running';
        } else if (key === 'complete') {
            label = s('status.complete', 'Complete'); state = 'complete';
        } else if (key === 'error') {
            label = s('status.error', 'Error');       state = 'error';
        } else {
            label = key;                              state = 'idle';
        }
        setFieldValue(this.root, '[data-check-status]', label, state);
    };

    ConnectionChecker.prototype.resetResults = function () {
        var DASH = '—';
        var selectors = [
            '[data-exit-ip]', '[data-exit-isp]', '[data-exit-location]', '[data-exit-asn]',
            '[data-webrtc-public]', '[data-webrtc-local]', '[data-webrtc-ipv6]', '[data-webrtc-mdns]'
        ];
        for (var i = 0; i < selectors.length; i++) {
            setText(this.root, selectors[i], DASH);
        }
        var compare = this.root.querySelector('[data-verdict-compare]');
        if (compare) {
            compare.setAttribute('hidden', '');
            setText(this.root, '[data-verdict-http-ip]', DASH);
            setText(this.root, '[data-verdict-webrtc-ip]', DASH);
        }
        this.lastHttp = null;
        this.lastSrflxIp = null;
        this.httpExitIp = null;
        this.observedUdpIp = null;
        this.observedTcpIp = null;
        this.observedStunIp = null;
        this.diag = {};
        this.webrtcBlocked = false;
        this.reportCandidates = null;
        this.rawCandidates = null;
        var turnBox = this.root.querySelector('[data-turn-box]');
        if (turnBox) {
            turnBox.setAttribute('data-tone', 'idle');
            setText(this.root, '[data-turn-title]', s('turn.checking', 'Checking…'));
            setText(this.root, '[data-turn-copy]', '');
            setText(this.root, '[data-turn-client-ip]', DASH);
            setText(this.root, '[data-turn-observed-stun-ip]', DASH);
            setText(this.root, '[data-turn-observed-ip]', DASH);
            setText(this.root, '[data-turn-observed-tcp-ip]', DASH);
        }
        var h3Box = this.root.querySelector('[data-h3-box]');
        if (h3Box) {
            h3Box.setAttribute('data-tone', 'idle');
            setText(this.root, '[data-h3-title]', s('h3.checking', 'Checking…'));
            setText(this.root, '[data-h3-copy]', '');
            setText(this.root, '[data-h3-proto]', DASH);
        }
        var exposedBox = this.root.querySelector('[data-exposed-box]');
        if (exposedBox) {
            exposedBox.setAttribute('hidden', '');
            exposedBox.setAttribute('data-tone', 'idle');
            var exposedList = this.root.querySelector('[data-exposed-list]');
            if (exposedList) exposedList.innerHTML = '';
        }
    };

    var roots = document.querySelectorAll('.nm-tool--conncheck');
    roots.forEach(function (root) {
        new ConnectionChecker(root).init();
    });
})();

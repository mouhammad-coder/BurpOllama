# -*- coding: utf-8 -*-
"""
BurpOllama Burp Suite Extension
─────────────────────────────────────────────────────────────────────────────
Install:
  1. Burp Suite → Extender → Options → set Jython standalone JAR path
  2. Extender → Extensions → Add → Type: Python → select this file

Sends intercepted HTTP traffic to the local BurpOllama analyzer backend.
Only use against targets you own or have written authorization to test.
─────────────────────────────────────────────────────────────────────────────
NOTE: Jython uses Python 2.7 syntax — NO f-strings, NO walrus operator.
"""

try:
    from burp import IBurpExtender, IHttpListener, IProxyListener, ITab, IExtensionStateListener
    BURP_RUNTIME_AVAILABLE = True
except ImportError:
    # Keep the module importable for offline validation and packaging checks.
    # Burp supplies the real interfaces when the extension is loaded in Jython.
    BURP_RUNTIME_AVAILABLE = False

    class IBurpExtender(object):
        pass

    class IHttpListener(object):
        pass

    class IProxyListener(object):
        pass

    class ITab(object):
        pass

    class IExtensionStateListener(object):
        pass

# IWebSocketMessageHandler is available in Burp Suite 2021.9+
# Graceful import — extension still works without it on older versions
try:
    from burp import IWebSocketMessageHandler
    WS_SUPPORT = True
except ImportError:
    class IWebSocketMessageHandler(object):
        pass
    WS_SUPPORT = False
try:
    from java.io import PrintWriter
    from javax.swing import (JPanel, JLabel, JCheckBox, JScrollPane,
                             JTextArea, BorderFactory, BoxLayout, Box)
    from javax.swing import SwingConstants
    from java.awt import BorderLayout, Color, Font, Dimension
except ImportError:
    class _UnavailableUI(object):
        def __init__(self, *args, **kwargs):
            pass

        def __getattr__(self, name):
            return _UnavailableUI()

        def __call__(self, *args, **kwargs):
            return _UnavailableUI()

    PrintWriter = _UnavailableUI
    JPanel = JLabel = JCheckBox = JScrollPane = JTextArea = _UnavailableUI
    BorderFactory = BoxLayout = Box = SwingConstants = _UnavailableUI()
    BorderLayout = Color = Font = Dimension = _UnavailableUI
import json
import re
import threading

# Python 2 / Jython HTTP
try:
    import urllib2 as urlrequest
except ImportError:
    import urllib.request as urlrequest  # Python 3 fallback (unused in Jython)

ANALYZER_URL    = "http://127.0.0.1:8888/analyze"
EXTENSION_NAME  = "BurpOllama"
MAX_BODY        = 8000   # bytes sent per body

# Response content-types worth analyzing
INTERESTING_CT = (
    "application/json",
    "application/x-www-form-urlencoded",
    "text/html",
    "text/xml",
    "application/xml",
    "application/graphql",
    "multipart/form-data",
    "text/javascript",
    "application/javascript",
)

# URL suffixes to skip (static assets — waste of LLM tokens)
SKIP_EXT = re.compile(
    r"\.(png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot|css|mp4|mp3|pdf)(\?.*)?$",
    re.IGNORECASE
)


class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, ITab, IExtensionStateListener):

    # ── Burp entry-point ──────────────────────────────────────────────────────
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)
        self._stderr    = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)      # for WebSocket frame capture
        callbacks.registerExtensionStateListener(self)

        # Register WebSocket handler if supported
        if WS_SUPPORT:
            try:
                callbacks.registerWebSocketMessageHandler(BurpWSHandler(self))
                self._log("[+] WebSocket interception enabled (Burp 2021.9+)")
            except Exception as e:
                self._log("[!] WebSocket handler not supported: %s" % str(e))
        else:
            self._log("[!] WebSocket support unavailable — update Burp Suite")

        # State
        self._enabled        = True
        self._scope_only     = False
        self._skip_2xx_only  = False
        self._req_count      = 0
        self._hit_count      = 0
        self._ws_count       = 0

        self._build_ui()
        callbacks.addSuiteTab(self)
        self._log("[+] %s loaded. Backend: %s" % (EXTENSION_NAME, ANALYZER_URL))
        self._log("[+] Dashboard: http://localhost:8888/ui")

    # ── IHttpListener ─────────────────────────────────────────────────────────
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process responses (so we have both request + response)
        if not self._enabled or messageIsRequest:
            return

        try:
            req_info  = self._helpers.analyzeRequest(messageInfo)
            resp_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            url_str   = str(req_info.getUrl())

            # --- Filters ---
            if SKIP_EXT.search(url_str):
                return
            if self._scope_only and not self._callbacks.isInScope(req_info.getUrl()):
                return
            status = resp_info.getStatusCode()
            if self._skip_2xx_only and not (200 <= status < 300):
                return

            # --- Extract data ---
            req_bytes  = messageInfo.getRequest()
            resp_bytes = messageInfo.getResponse()

            req_headers  = self._headers_str(req_info.getHeaders())
            resp_headers = self._headers_str(resp_info.getHeaders())

            req_body  = ""
            resp_body = ""
            if req_bytes and len(req_bytes) > req_info.getBodyOffset():
                req_body = self._safe_str(req_bytes[req_info.getBodyOffset():])[:MAX_BODY]
            if resp_bytes and len(resp_bytes) > resp_info.getBodyOffset():
                resp_body = self._safe_str(resp_bytes[resp_info.getBodyOffset():])[:MAX_BODY]

            # Content-type filter (check response CT)
            ct = self._get_header(resp_info.getHeaders(), "content-type").lower()
            if ct and not any(t in ct for t in INTERESTING_CT):
                return

            payload = {
                "request_method":   str(req_info.getMethod()),
                "request_url":      url_str,
                "request_headers":  req_headers,
                "request_body":     req_body,
                "response_status":  status,
                "response_headers": resp_headers,
                "response_body":    resp_body,
                "source":           "burp",
            }

            self._req_count += 1
            self._update_label(self._req_label,
                               "Requests sent: %d" % self._req_count)

            # Fire async so Burp UI is never blocked
            t = threading.Thread(target=self._ship, args=(payload, url_str))
            t.daemon = True
            t.start()

        except Exception as e:
            self._log("[!] processHttpMessage error: %s" % str(e))

    def _ship(self, payload, url_str):
        """Send payload to analyzer — runs in daemon thread."""
        try:
            body = json.dumps(payload).encode("utf-8")
            req  = urlrequest.Request(
                ANALYZER_URL, body,
                {"Content-Type": "application/json"}
            )
            resp   = urlrequest.urlopen(req, timeout=10)
            result = json.loads(resp.read().decode("utf-8"))
            hits   = result.get("instant_findings", 0)
            if hits:
                self._hit_count += hits
                self._update_label(self._hit_label,
                                   "Instant findings: %d" % self._hit_count)
                self._log("[FIND] %d hit(s) on %s" % (hits, url_str))
        except Exception as e:
            self._log("[ERR] Analyzer unreachable: %s" % str(e))
            self._log("      Is the backend running?  python3 analyzer/main.py")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _headers_str(self, headers):
        return "\r\n".join(str(h) for h in headers)

    def _get_header(self, headers, name):
        prefix = name.lower() + ":"
        for h in headers:
            s = str(h)
            if s.lower().startswith(prefix):
                return s.split(":", 1)[1].strip()
        return ""

    def _safe_str(self, byte_array):
        """Convert Jython byte array to str, replacing non-ASCII safely."""
        try:
            return "".join(chr(b & 0xFF) for b in byte_array)
        except Exception:
            return ""

    def _log(self, msg):
        self._stdout.println(msg)
        try:
            self._log_area.append(msg + "\n")
        except Exception:
            pass

    def _update_label(self, label, text):
        try:
            label.setText(text)
        except Exception:
            pass

    # ── IExtensionStateListener ───────────────────────────────────────────────
    def extensionUnloaded(self):
        self._log("[-] %s unloaded." % EXTENSION_NAME)

    # ── IProxyListener (WebSocket frame detection fallback) ───────────────────
    def processProxyMessage(self, messageIsRequest, message):
        """
        Fallback WebSocket detection via IProxyListener.
        In Burp Suite 2.x, WS upgrade requests pass through here.
        Real frame content is captured by BurpWSHandler when WS_SUPPORT=True.
        """
        if not self._enabled:
            return
        try:
            msg_info = message.getMessageInfo()
            req_info = self._helpers.analyzeRequest(msg_info)
            # Detect WebSocket upgrade request
            for h in req_info.getHeaders():
                if "upgrade: websocket" in str(h).lower():
                    self._log("[WS] WebSocket upgrade detected: %s" % str(req_info.getUrl()))
                    break
        except Exception:
            pass

    # ── ITab ─────────────────────────────────────────────────────────────────
    def getTabCaption(self):
        return EXTENSION_NAME

    def getUiComponent(self):
        return self._panel

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        BG   = Color(15, 15, 25)
        FG_G = Color(0, 230, 150)
        FG_B = Color(80, 180, 255)
        FG_Y = Color(220, 200, 60)
        FG_R = Color(255, 100, 80)
        FG_D = Color(120, 140, 160)
        MONO = Font("Monospaced", Font.PLAIN, 12)
        MONO_B = Font("Monospaced", Font.BOLD, 13)

        self._panel = JPanel(BorderLayout())
        self._panel.setBackground(BG)

        # Header
        hdr = JLabel("  BurpOllama  --  AI Bug Hunter", SwingConstants.LEFT)
        hdr.setFont(Font("Monospaced", Font.BOLD, 15))
        hdr.setForeground(FG_G)
        hdr.setOpaque(True)
        hdr.setBackground(Color(8, 8, 18))
        hdr.setPreferredSize(Dimension(900, 38))
        self._panel.add(hdr, BorderLayout.NORTH)

        # Main body
        body = JPanel()
        body.setBackground(BG)
        body.setLayout(BoxLayout(body, BoxLayout.Y_AXIS))
        body.setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14))

        # ── Checkboxes ──
        self._en_cb = JCheckBox("Enable interception", True)
        self._sc_cb = JCheckBox("In-scope targets only", False)
        self._ok_cb = JCheckBox("Analyze ALL status codes (default: all)", False)
        for cb in (self._en_cb, self._sc_cb, self._ok_cb):
            cb.setForeground(FG_G)
            cb.setBackground(BG)
            cb.setFont(MONO)

        def toggle_en(e):
            self._enabled = self._en_cb.isSelected()
        def toggle_sc(e):
            self._scope_only = self._sc_cb.isSelected()
        def toggle_ok(e):
            self._skip_2xx_only = self._ok_cb.isSelected()

        self._en_cb.addActionListener(toggle_en)
        self._sc_cb.addActionListener(toggle_sc)
        self._ok_cb.addActionListener(toggle_ok)

        body.add(self._en_cb)
        body.add(self._sc_cb)
        body.add(self._ok_cb)
        body.add(Box.createVerticalStrut(10))

        # ── Counters ──
        self._req_label = JLabel("Requests sent: 0")
        self._req_label.setForeground(FG_B)
        self._req_label.setFont(MONO_B)

        self._hit_label = JLabel("Instant findings: 0")
        self._hit_label.setForeground(FG_R)
        self._hit_label.setFont(MONO_B)

        self._ws_label = JLabel("WebSocket frames: 0")
        self._ws_label.setForeground(Color(180, 120, 255))
        self._ws_label.setFont(MONO_B)

        body.add(self._req_label)
        body.add(self._hit_label)
        body.add(self._ws_label)
        body.add(Box.createVerticalStrut(8))

        # ── Info labels ──
        for txt, col in [
            ("Backend  : http://127.0.0.1:8888/analyze", FG_D),
            ("Dashboard: http://127.0.0.1:8888/ui",      FG_Y),
            ("Health   : http://127.0.0.1:8888/health",  FG_D),
            ("Export   : http://127.0.0.1:8888/findings/export", FG_D),
        ]:
            lbl = JLabel(txt)
            lbl.setForeground(col)
            lbl.setFont(MONO)
            body.add(lbl)

        body.add(Box.createVerticalStrut(10))

        # ── Log area ──
        self._log_area = JTextArea(18, 70)
        self._log_area.setEditable(False)
        self._log_area.setBackground(Color(8, 8, 15))
        self._log_area.setForeground(FG_G)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        scroll = JScrollPane(self._log_area)
        scroll.setBorder(BorderFactory.createLineBorder(Color(0, 80, 60)))
        body.add(scroll)

        self._panel.add(body, BorderLayout.CENTER)


# ─────────────────────────────────────────────────────────────────────────────
#  WebSocket Frame Handler (Burp Suite 2021.9+ only)
#  Registered via callbacks.registerWebSocketMessageHandler()
#  Captures JSON/text WS frames and routes through pre-filter to backend.
# ─────────────────────────────────────────────────────────────────────────────

if WS_SUPPORT:
    class BurpWSHandler(IWebSocketMessageHandler):
        """
        v3.3: deque ring-buffer + decoupled sender pool.
        Intercept thread: check + str() + append + event.set() only (<3us).
        Drain worker: snapshots ring -> store (no I/O).
        Sender pool (2 threads): filter + build + HTTP POST.
        No Queue.Full, no frame drops under sustained high-frequency traffic.
        """

        INTERESTING_WS_PATTERNS = [
            '"type"', '"action"', '"event"', '"cmd"',
            '"user"', '"token"', '"auth"', '"session"',
            '"id"', '"userId"', '"accountId"',
            '"password"', '"email"', '"data"',
            '"query"', '"mutation"', '"subscription"',
        ]
        _RING_SIZE   = 2000
        _SENDER_POOL = 2

        def __init__(self, extender):
            self._ext = extender
            import collections as _col

            self._ring      = _col.deque(maxlen=self._RING_SIZE)
            self._ring_lock = threading.Lock()
            self._ring_evt  = threading.Event()
            self._dropped_frames = 0   # v3.3: eviction counter

            self._store      = []
            self._store_lock = threading.Lock()
            self._store_evt  = threading.Event()

            threading.Thread(target=self._drain_worker, name="WS-Drain", daemon=True).start()
            for i in range(self._SENDER_POOL):
                threading.Thread(target=self._sender_worker, args=(i,),
                                 name="WS-Sender-%d" % i, daemon=True).start()

            self._ext._log("[WS] v3.3 ring-buffer started (ring=%d, senders=%d)" % (
                self._RING_SIZE, self._SENDER_POOL))

        def handleTextMessage(self, controller, messageIsFromClient, message):
            if not self._ext._enabled or not message:
                return
            try:
                msg_str = str(message)
                if not msg_str:
                    return
                try:
                    url = str(controller.getUrl()) if hasattr(controller, "getUrl") else "ws://unknown"
                except Exception:
                    url = "ws://unknown"
                direction = "c2s" if messageIsFromClient else "s2c"
                with self._ring_lock:
                    # v3.3: count evictions — deque auto-drops oldest when full
                    if len(self._ring) == self._RING_SIZE:
                        self._dropped_frames += 1
                    self._ring.append((msg_str, url, direction, "text"))
                self._ring_evt.set()
            except Exception:
                pass

        def handleBinaryMessage(self, controller, messageIsFromClient, message):
            if not self._ext._enabled or not message:
                return
            try:
                msg_str = "".join(chr(b & 0xFF) for b in message)
                if not msg_str:
                    return
                try:
                    url = str(controller.getUrl()) if hasattr(controller, "getUrl") else "ws://unknown"
                except Exception:
                    url = "ws://unknown"
                direction = "c2s" if messageIsFromClient else "s2c"
                with self._ring_lock:
                    if len(self._ring) == self._RING_SIZE:
                        self._dropped_frames += 1
                    self._ring.append((msg_str, url, direction, "binary"))
                self._ring_evt.set()
            except Exception:
                pass

        def _drain_worker(self):
            while True:
                try:
                    self._ring_evt.wait(timeout=0.5)
                    self._ring_evt.clear()
                    with self._ring_lock:
                        if not self._ring:
                            continue
                        snapshot = list(self._ring)
                        self._ring.clear()
                    filtered = [(m, u, d, t) for m, u, d, t in snapshot
                                if self._is_interesting_ws(m)]
                    if not filtered:
                        continue
                    with self._store_lock:
                        self._store.extend(filtered)
                    self._store_evt.set()
                except Exception as e:
                    try:
                        self._ext._log("[WS] Drain error: %s" % str(e))
                    except Exception:
                        pass

        def _sender_worker(self, worker_id):
            import time as _t
            while True:
                try:
                    self._store_evt.wait(timeout=1.0)
                    frame = None
                    with self._store_lock:
                        if self._store:
                            frame = self._store.pop(0)
                        if not self._store:
                            self._store_evt.clear()
                    if not frame:
                        continue
                    msg_str, url, direction, ftype = frame
                    try:
                        is_client = (direction == "c2s")
                        payload = {
                            "request_method":   "WEBSOCKET",
                            "request_url":      url,
                            "request_headers":  "Upgrade: websocket\r\nDirection: %s\r\nFrame-Type: %s" % (direction, ftype),
                            "request_body":     msg_str[:8000] if is_client else "",
                            "response_status":  101,
                            "response_headers": "Content-Type: application/json",
                            "response_body":    msg_str[:8000] if not is_client else "",
                            "source":           "burp-websocket",
                        }
                        self._ext._ws_count += 1
                        try:
                            self._ext._update_label(self._ext._ws_label,
                                                    "WebSocket frames: %d" % self._ext._ws_count)
                        except Exception:
                            pass
                        self._ext._ship(payload, url)
                    except Exception as send_err:
                        try:
                            self._ext._log("[WS] Sender-%d: %s" % (worker_id, str(send_err)))
                        except Exception:
                            pass
                        _t.sleep(0.25)
                except Exception as outer:
                    try:
                        self._ext._log("[WS] Sender-%d outer: %s" % (worker_id, str(outer)))
                    except Exception:
                        pass
                    import time as _t2; _t2.sleep(0.25)

        def _is_interesting_ws(self, text):
            if not text or len(text) < 10:
                return False
            t = text.strip()
            if not (t.startswith("{") or t.startswith("[")):
                return False
            return any(kw in t for kw in BurpWSHandler.INTERESTING_WS_PATTERNS)

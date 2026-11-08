#!/usr/bin/env python3
"""passive-scan: an example Loupe extension.

It reads one JSON event per line on stdin and writes one JSON message per line
on stdout. For every http.response event it inspects the exchange and reports
issues. This is a reference you can copy: an extension is just a program that
speaks this tiny line-delimited JSON protocol, in any language.

    in : {"type":"http.response","flow":12,"method":"GET","url":"...",
          "host":"...","status":200,"request":"<base64>","response":"<base64>"}
    out: {"type":"issue","flow":12,"name":"...","severity":"High",
          "detail":"...","evidence":"..."}
    out: {"type":"log","message":"..."}
"""
import base64
import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl

SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Bearer/secret assignment", re.compile(r"(?i)(?:api[_-]?key|secret|password|passwd|token)\"?\s*[:=]\s*\"[^\"]{8,}\"")),
]

seen = set()


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def issue(flow, name, severity, detail, evidence=""):
    key = (name, flow, (evidence or detail)[:60])
    if key in seen:
        return
    seen.add(key)
    emit({"type": "issue", "flow": flow, "name": name, "severity": severity,
          "detail": detail, "evidence": evidence[:300]})


def split_message(raw):
    i = raw.find(b"\r\n\r\n")
    sep = 4
    if i < 0:
        i = raw.find(b"\n\n")
        sep = 2
    if i < 0:
        return raw, b""
    return raw[:i], raw[i + sep:]


def headers_of(head):
    out = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            out.setdefault(k.strip().lower().decode("latin1"), v.strip().decode("latin1", "replace"))
    return out, [line for line in head.split(b"\r\n")[1:]]


def multi(head, name):
    name = name.lower().encode()
    vals = []
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            if k.strip().lower() == name:
                vals.append(v.strip().decode("latin1", "replace"))
    return vals


def scan(ev):
    flow = ev.get("flow", 0)
    url = ev.get("url", "")
    status = ev.get("status", 0)
    req = base64.b64decode(ev.get("request", "") or "")
    resp = base64.b64decode(ev.get("response", "") or "")
    rhead, _ = split_message(req)
    shead, sbody = split_message(resp)
    h, _ = headers_of(shead)
    parts = urlsplit(url)
    is_https = parts.scheme == "https"
    ctype = h.get("content-type", "")
    is_html = "text/html" in ctype

    # 1) Missing security headers on HTML pages.
    if is_html and 200 <= status < 400:
        if "content-security-policy" not in h:
            issue(flow, "Missing Content-Security-Policy", "Low",
                  "The HTML response has no Content-Security-Policy header, which would mitigate XSS and data injection.",
                  parts.path or "/")
        if "x-content-type-options" not in h:
            issue(flow, "Missing X-Content-Type-Options", "Info",
                  "No 'X-Content-Type-Options: nosniff' header; browsers may MIME-sniff the response.", parts.path or "/")
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            issue(flow, "Missing clickjacking protection", "Low",
                  "No X-Frame-Options or CSP frame-ancestors; the page may be framed for clickjacking.", parts.path or "/")
        if is_https and "strict-transport-security" not in h:
            issue(flow, "Missing Strict-Transport-Security", "Low",
                  "HTTPS response without HSTS; connections can be downgraded to HTTP.", parts.path or "/")

    # 2) Server technology disclosure.
    for header in ("server", "x-powered-by", "x-aspnet-version"):
        if header in h and any(c.isdigit() for c in h[header]):
            issue(flow, "Server version disclosure", "Info",
                  "A response header reveals software and version, aiding targeted attacks.",
                  header + ": " + h[header])

    # 3) Insecure cookies.
    for cookie in multi(shead, "set-cookie"):
        low = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        flags = []
        if "httponly" not in low:
            flags.append("HttpOnly")
        if is_https and "secure" not in low:
            flags.append("Secure")
        if flags:
            issue(flow, "Cookie without " + " and ".join(flags), "Low",
                  "The cookie '%s' is set without the %s flag." % (name, "/".join(flags)), cookie[:120])

    # 4) Reflected query parameters (possible XSS/HTML injection).
    if is_html and sbody:
        body_txt = sbody.decode("latin1", "replace")
        for key, value in parse_qsl(parts.query, keep_blank_values=False):
            if len(value) >= 4 and value in body_txt:
                issue(flow, "Reflected parameter in response", "Medium",
                      "The value of parameter '%s' is reflected unescaped in the HTML response; test for XSS." % key,
                      "%s=%s" % (key, value))

    # 5) Secrets exposed in the response body.
    body_txt = sbody.decode("latin1", "replace")
    for label, pat in SECRET_PATTERNS:
        m = pat.search(body_txt)
        if m:
            found = m.group(0)
            redacted = found[:6] + "…" + found[-4:] if len(found) > 14 else found
            issue(flow, "Possible secret in response: " + label, "High",
                  "A string matching %s was found in the response body." % label, redacted)


def main():
    emit({"type": "hello", "name": "passive-scan", "version": "1.0.0", "events": ["http.response"]})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("type") == "http.response":
            try:
                scan(ev)
            except Exception as e:  # never die on one bad message
                emit({"type": "log", "message": "scan error: %r" % e})


if __name__ == "__main__":
    main()

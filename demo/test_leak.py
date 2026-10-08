"""Accidental external network call demo."""
import urllib.request
import sys

print("[!] Attempting external call to http://example.com ...", flush=True)
try:
    req = urllib.request.Request("http://example.com", headers={"User-Agent": "nullroute-demo"})
    with urllib.request.urlopen(req, timeout=2) as resp:
        print(f"[+] Leaked call succeeded! HTTP {resp.status} OK", flush=True)
except Exception as e:
    print(f"[-] Blocked by network boundary: {e}", file=sys.stderr, flush=True)
    sys.exit(1)

"""Example test suite with an accidental external API call.

In a clean hermetic build or CI run, tests should never touch external services.
Without nullroute, this test silently reaches out and succeeds (or flakes when external API is down).
With nullroute, this test is instantly blocked without code changes.
"""

import sys
import urllib.request
import unittest

class TestPaymentClient(unittest.TestCase):
    def test_mocked_local_calculation(self):
        """Pure unit test that always succeeds."""
        tax = 100 * 0.08
        self.assertEqual(tax, 8.0)

    def test_accidental_external_network_call(self):
        """Simulates an unmocked client leaking out to external network."""
        print("\n[!] Attempting external call to https://api.github.com/zen ...", file=sys.stderr)
        req = urllib.request.Request(
            "https://api.github.com/zen",
            headers={"User-Agent": "nullroute-demo"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            zen = resp.read().decode("utf-8").strip()
            print(f"[+] Leaked call succeeded! Zen: '{zen}'", file=sys.stderr)
            self.assertTrue(len(zen) > 0)

if __name__ == "__main__":
    unittest.main()

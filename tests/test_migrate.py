from ise_cert_utility import cli

LEGACY_SCRIPT = """#!/usr/bin/env python3
from pathlib import Path
BASE = Path('/etc/ise-cert-sync')
DOMAIN = 'ise-01.example.net'
NODE = 'ISE-01'
TAG = 'Default Portal Certificate Group'
LINEAGE = Path('/etc/letsencrypt/live') / DOMAIN
EAP = '32c3164c419eb54fb67587334d205cb98eb1085144ad5eef8601a6117e75bc1a'
"""


def test_reads_legacy_script_constants(tmp_path):
    script = tmp_path / "ise-cert-sync.py"
    script.write_text(LEGACY_SCRIPT)
    assert cli._legacy_constants(script) == {
        "domain": "ise-01.example.net", "node": "ISE-01", "portal_tag": "Default Portal Certificate Group",
        "eap_fingerprint": "32c3164c419eb54fb67587334d205cb98eb1085144ad5eef8601a6117e75bc1a"}


def test_missing_or_broken_legacy_script(tmp_path):
    assert cli._legacy_constants(tmp_path / "absent.py") == {}
    broken = tmp_path / "broken.py"
    broken.write_text("DOMAIN = (")
    assert cli._legacy_constants(broken) == {}

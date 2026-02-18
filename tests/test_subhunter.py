"""
SubHunter v5.0 - Test Suite

Tests for core functionality, security, and CLI argument parsing.
Run with: python -m pytest tests/ -v
"""
import asyncio
import re
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ──────────────────────────────────────────────────────────────────────────────
# Domain Validation Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestDomainValidation:
    """Test domain input validation."""

    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )

    @pytest.mark.parametrize("domain", [
        "example.com",
        "sub.example.com",
        "deep.sub.example.com",
        "example.co.uk",
        "test-domain.org",
        "a.io",
    ])
    def test_valid_domains(self, domain):
        assert self.DOMAIN_PATTERN.match(domain), f"{domain} should be valid"

    @pytest.mark.parametrize("domain", [
        "",
        "not_a_domain",
        ".example.com",
        "example.",
        "-example.com",
        "example-.com",
        "exam ple.com",
        "example..com",
    ])
    def test_invalid_domains(self, domain):
        assert not self.DOMAIN_PATTERN.match(domain), f"{domain} should be invalid"


# ──────────────────────────────────────────────────────────────────────────────
# Cloud Provider Detection Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestCloudDetection:
    """Test cloud provider detection logic."""

    def test_detect_aws_from_cname(self):
        from core.cloud import detect_cloud_from_cname
        assert detect_cloud_from_cname("bucket.s3.amazonaws.com") == "AWS"
        assert detect_cloud_from_cname("app.elasticbeanstalk.com") == "AWS"
        assert detect_cloud_from_cname("dist.cloudfront.net") == "AWS"

    def test_detect_azure_from_cname(self):
        from core.cloud import detect_cloud_from_cname
        assert detect_cloud_from_cname("app.azurewebsites.net") == "Azure"
        assert detect_cloud_from_cname("storage.blob.core.windows.net") == "Azure"

    def test_detect_cloudflare_from_cname(self):
        from core.cloud import detect_cloud_from_cname
        assert detect_cloud_from_cname("proxy.cdn.cloudflare.net") == "Cloudflare"

    def test_detect_github_from_cname(self):
        from core.cloud import detect_cloud_from_cname
        assert detect_cloud_from_cname("user.github.io") == "GitHub"

    def test_detect_heroku_from_cname(self):
        from core.cloud import detect_cloud_from_cname
        assert detect_cloud_from_cname("myapp.herokuapp.com") == "Heroku"

    def test_unknown_cname(self):
        from core.cloud import detect_cloud_from_cname
        assert detect_cloud_from_cname("unknown.randomdomain.com") is None
        assert detect_cloud_from_cname(None) is None
        assert detect_cloud_from_cname("") is None

    def test_detect_cloudflare_from_headers(self):
        from core.cloud import detect_cloud_from_headers
        headers = {"server": "cloudflare", "cf-ray": "abc123"}
        assert detect_cloud_from_headers(headers) == "Cloudflare"

    def test_detect_vercel_from_headers(self):
        from core.cloud import detect_cloud_from_headers
        headers = {"x-vercel-id": "abc123"}
        assert detect_cloud_from_headers(headers) == "Vercel"

    def test_no_headers(self):
        from core.cloud import detect_cloud_from_headers
        assert detect_cloud_from_headers(None) is None
        assert detect_cloud_from_headers({}) is None

    def test_priority_cname_over_ip(self):
        from core.cloud import detect_cloud_provider
        # CNAME says AWS, IP might say something else
        result = detect_cloud_provider(
            ip="104.18.1.1",  # Cloudflare IP range
            cname="bucket.s3.amazonaws.com"
        )
        assert result == "AWS"  # CNAME takes priority

    def test_cloud_color_mapping(self):
        from core.cloud import get_cloud_color
        assert get_cloud_color("AWS") != ""
        assert get_cloud_color("Unknown") == "\033[0m"


# ──────────────────────────────────────────────────────────────────────────────
# Wildcard Detection Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestWildcardDetection:
    """Test wildcard DNS detection logic."""

    def test_wildcard_result_str(self):
        from core.wildcard import WildcardResult
        result = WildcardResult(is_wildcard=True, wildcard_ips={"1.2.3.4"}, tested_subdomains=5)
        assert "Wildcard detected" in str(result)
        assert "1.2.3.4" in str(result)

    def test_no_wildcard_result_str(self):
        from core.wildcard import WildcardResult
        result = WildcardResult(is_wildcard=False, wildcard_ips=set(), tested_subdomains=5)
        assert "No wildcard" in str(result)

    def test_random_subdomain_generation(self):
        from core.wildcard import generate_random_subdomain
        sub1 = generate_random_subdomain()
        sub2 = generate_random_subdomain()
        assert len(sub1) == 12
        assert sub1 != sub2  # Extremely unlikely to be equal
        assert sub1.isalnum()

    def test_filter_wildcard_results(self):
        from core.wildcard import filter_wildcard_results
        subdomains = {"a.example.com", "b.example.com", "c.example.com"}
        resolved = {
            "a.example.com": {"1.2.3.4"},
            "b.example.com": {"1.2.3.4"},
            "c.example.com": {"5.6.7.8"},
        }
        wildcard_ips = {"1.2.3.4"}

        filtered, removed = filter_wildcard_results(subdomains, resolved, wildcard_ips)
        assert "c.example.com" in filtered
        assert "a.example.com" not in filtered
        assert removed == 2

    def test_filter_no_wildcards(self):
        from core.wildcard import filter_wildcard_results
        subdomains = {"a.example.com"}
        resolved = {"a.example.com": {"1.2.3.4"}}
        filtered, removed = filter_wildcard_results(subdomains, resolved, set())
        assert filtered == subdomains
        assert removed == 0


# ──────────────────────────────────────────────────────────────────────────────
# Report XSS Safety Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestReportSecurity:
    """Test that HTML reports are XSS-safe."""

    def test_esc_function(self):
        from core.report import esc
        assert esc("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
        assert esc(None) == ""
        assert esc("normal text") == "normal text"
        assert esc('He said "hello"') == "He said &quot;hello&quot;"
        assert esc("It's fine") == "It&#x27;s fine"

    def test_report_generation_with_xss_payload(self):
        from core.report import generate_html_report
        # Simulate a probe result with XSS in subdomain/title
        probe_results = [{
            "subdomain": '<img src=x onerror=alert(1)>',
            "ip": "1.2.3.4",
            "alive": True,
            "url": "http://example.com",
            "final_url": "http://example.com",
            "status": 200,
            "title": '<script>alert("xss")</script>',
            "tech": ["Nginx"],
            "server": "nginx",
            "content_type": "text/html",
            "content_length": 1234,
            "response_time": 100,
            "headers": {},
            "redirect_chain": [],
            "cookies": [],
            "meta_description": None,
            "protocol": "HTTP",
            "cloud_provider": None,
            "cname": None,
        }]

        html = generate_html_report("example.com", probe_results)
        # XSS payloads must be escaped
        assert '<script>alert' not in html
        assert '<img src=x onerror' not in html
        assert '&lt;script&gt;' in html

    def test_report_generation_empty(self):
        from core.report import generate_html_report
        html = generate_html_report("example.com", [])
        assert "SubHunter" in html
        assert "example.com" in html


# ──────────────────────────────────────────────────────────────────────────────
# Configuration Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestConfig:
    """Test configuration constants."""

    def test_default_wordlist_not_empty(self):
        from utils.config import DEFAULT_WORDLIST
        assert len(DEFAULT_WORDLIST) > 50
        assert "www" in DEFAULT_WORDLIST
        assert "admin" in DEFAULT_WORDLIST
        assert "api" in DEFAULT_WORDLIST

    def test_common_ports_valid(self):
        from utils.config import COMMON_PORTS
        assert 80 in COMMON_PORTS
        assert 443 in COMMON_PORTS
        assert 22 in COMMON_PORTS
        assert all(1 <= p <= 65535 for p in COMMON_PORTS)

    def test_tech_signatures_format(self):
        from utils.config import TECH_SIGNATURES
        assert "WordPress" in TECH_SIGNATURES
        assert "Nginx" in TECH_SIGNATURES
        assert isinstance(TECH_SIGNATURES["WordPress"], list)
        assert len(TECH_SIGNATURES["WordPress"]) > 0


# ──────────────────────────────────────────────────────────────────────────────
# Display Module Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestDisplay:
    """Test display utilities."""

    def test_version_is_5(self):
        from utils.display import VERSION
        assert VERSION == "5.0"

    def test_colors_have_reset(self):
        from utils.display import Colors
        assert Colors.RESET == '\033[0m'
        assert Colors.GREEN != ""
        assert Colors.RED != ""

    def test_print_banner(self, capsys):
        from utils.display import print_banner
        print_banner()
        captured = capsys.readouterr()
        assert "SubHunter" in captured.out or "SUBHUNTER" in captured.out or "v5.0" in captured.out


# ──────────────────────────────────────────────────────────────────────────────
# CLI Argument Parsing Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestCLI:
    """Test CLI argument parsing."""

    def _parse(self, args_str: str):
        """Helper to parse CLI args."""
        import argparse
        from utils.display import VERSION

        parser = argparse.ArgumentParser()
        parser.add_argument("-d", "--domain", required=True)
        parser.add_argument("-w", "--wordlist")
        parser.add_argument("-o", "--output")
        parser.add_argument("--html")
        parser.add_argument("--no-brute", action="store_true")
        parser.add_argument("--no-probe", action="store_true")
        parser.add_argument("--ports", action="store_true")
        parser.add_argument("--screenshots", action="store_true")
        parser.add_argument("--resume", action="store_true")
        parser.add_argument("-c", "--concurrency", type=int, default=100)
        parser.add_argument("-q", "--quiet", action="store_true")
        parser.add_argument("--recursive", action="store_true")
        parser.add_argument("--recursive-depth", type=int, default=2)
        parser.add_argument("--no-wildcard-filter", action="store_true")
        parser.add_argument("--takeover", action="store_true")
        parser.add_argument("--vhost", action="store_true")
        parser.add_argument("--js-parse", action="store_true")
        parser.add_argument("--interactive", action="store_true")
        return parser.parse_args(args_str.split())

    def test_basic_domain(self):
        args = self._parse("-d example.com")
        assert args.domain == "example.com"

    def test_recursive_flags(self):
        args = self._parse("-d example.com --recursive --recursive-depth 3")
        assert args.recursive is True
        assert args.recursive_depth == 3

    def test_no_wildcard_flag(self):
        args = self._parse("-d example.com --no-wildcard-filter")
        assert args.no_wildcard_filter is True

    def test_v5_features(self):
        args = self._parse("-d example.com --takeover --vhost --js-parse")
        assert args.takeover is True
        assert args.vhost is True
        assert args.js_parse is True

    def test_concurrency(self):
        args = self._parse("-d example.com -c 50")
        assert args.concurrency == 50

    def test_full_scan_flags(self):
        args = self._parse("-d example.com --ports --screenshots --recursive --takeover --vhost --js-parse -o results.json")
        assert args.ports is True
        assert args.screenshots is True
        assert args.recursive is True
        assert args.output == "results.json"


# ──────────────────────────────────────────────────────────────────────────────
# Takeover Signatures Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestTakeoverSignatures:
    """Test takeover detection signatures."""

    def test_signatures_loaded(self):
        from core.takeover import TAKEOVER_SIGNATURES
        assert len(TAKEOVER_SIGNATURES) >= 20
        assert "github.io" in TAKEOVER_SIGNATURES
        assert "herokuapp.com" in TAKEOVER_SIGNATURES
        assert "amazonaws.com" in TAKEOVER_SIGNATURES

    def test_each_signature_has_fingerprints(self):
        from core.takeover import TAKEOVER_SIGNATURES
        for service, fingerprints in TAKEOVER_SIGNATURES.items():
            assert isinstance(fingerprints, list), f"{service} fingerprints should be a list"
            assert len(fingerprints) > 0, f"{service} should have at least one fingerprint"


# ──────────────────────────────────────────────────────────────────────────────
# State Management Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestStateManagement:
    """Test save/load/clear state functionality."""

    def test_save_and_load_state(self, tmp_path):
        from unittest.mock import patch
        import json

        state_file = tmp_path / "test_state.json"

        with patch("subhunter.STATE_FILE", str(state_file)):
            from subhunter import save_state, load_state, clear_state

            save_state("example.com", {"sub1.example.com", "sub2.example.com"}, "passive")

            state = json.loads(state_file.read_text())
            assert state["domain"] == "example.com"
            assert len(state["subdomains"]) == 2
            assert state["phase"] == "passive"

    def test_load_nonexistent_state(self, tmp_path):
        from unittest.mock import patch

        with patch("subhunter.STATE_FILE", str(tmp_path / "nonexistent.json")):
            from subhunter import load_state
            assert load_state() is None

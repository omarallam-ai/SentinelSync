from app.domain.types import IOCType
from app.services.extract import extract_iocs


def test_extract_finds_url_ip_domain_sha256():
    text = """
    Check https://Example.com/path?q=1 and IP 8.8.8.8
    suspicious domain sub.evil-example.org
    sha256: a3" not real
    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    """
    out = extract_iocs(text)
    types = [x.ioc_type for x in out]
    assert IOCType.url in types
    assert IOCType.ip in types
    assert IOCType.domain in types
    assert IOCType.hash_sha256 in types


def test_extract_url_keeps_original_raw():
    text = "Go to https://EXAMPLE.com/A#frag"
    out = extract_iocs(text)
    assert any(x.raw == "https://EXAMPLE.com/A#frag" for x in out)


def test_extract_does_not_match_file_extensions_as_domains():
    """gate.php, dropper.exe, payload.dll etc. must NOT be extracted as domains."""
    text = "Downloaded gate.php and dropper.exe and payload.dll and invoice.pdf"
    out = extract_iocs(text)
    domain_values = [x.raw for x in out if x.ioc_type == IOCType.domain]
    assert "gate.php" not in domain_values
    assert "dropper.exe" not in domain_values
    assert "payload.dll" not in domain_values
    assert "invoice.pdf" not in domain_values


def test_extract_real_domains_still_work_after_filter():
    """Legitimate domains with real TLDs must still be extracted."""
    text = "Contact evil.com and bad-actor.net and phish.org"
    out = extract_iocs(text)
    domain_values = [x.raw for x in out if x.ioc_type == IOCType.domain]
    assert any("evil.com" in v for v in domain_values)
    assert any("bad-actor.net" in v for v in domain_values)
    assert any("phish.org" in v for v in domain_values)


def test_extract_domain_inside_url_not_double_captured():
    """A domain that appears inside a URL should not also be extracted as a bare domain."""
    text = "See http://evil-phish.net/login for details"
    out = extract_iocs(text)
    urls = [x for x in out if x.ioc_type == IOCType.url]
    domains = [x for x in out if x.ioc_type == IOCType.domain and x.raw == "evil-phish.net"]
    assert len(urls) == 1
    # The domain inside the URL should not be double-captured
    assert len(domains) == 0
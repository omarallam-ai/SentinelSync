from app.domain.types import IOCType
from app.services.normalize import normalize


def test_normalize_domain_lower_and_strip_dot():
    assert normalize(IOCType.domain, "Example.COM.") == "example.com"


def test_normalize_sha256_lower():
    raw = "ABCDEF" * 10 + "ABCD"
    raw = (raw + "0" * (64 - len(raw)))[:64]
    assert normalize(IOCType.hash_sha256, raw).islower()


def test_normalize_url_canonicalizes_scheme_host_and_drops_fragment():
    raw = "HTTPS://Example.COM/Path?Q=1#frag"
    assert normalize(IOCType.url, raw) == "https://example.com/Path?Q=1"
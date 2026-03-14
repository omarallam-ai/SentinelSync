from app.core.logging import get_correlation_id, set_correlation_id


def test_correlation_id_is_set_and_stable():
    cid = set_correlation_id("abc123")
    assert cid == "abc123"
    assert get_correlation_id() == "abc123"
import json

import httpx

from app.services.passive_recon import _ct_names, _valid_hostname


def test_valid_hostname_normalizes_and_rejects_invalid_values():
    assert _valid_hostname("*.Example.com") == "example.com"
    assert _valid_hostname("API.Example.com.") == "api.example.com"
    assert _valid_hostname("127.0.0.1") is None
    assert _valid_hostname("https://example.com/path") is None
    assert _valid_hostname("-bad.example.com") is None


def test_ct_lookup_includes_root_and_descendants():
    requested = []

    def handler(request):
        query = request.url.params.get("q")
        requested.append(query)
        if query == "example.com":
            body = [{"name_value": "example.com"}]
        else:
            body = [{"name_value": "api.example.com\n*.cdn.example.com\noutside.test"}]
        return httpx.Response(200, json=body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        names, message = _ct_names(client, "example.com")

    assert requested == ["example.com", "%.example.com"]
    assert names == {"example.com", "api.example.com", "cdn.example.com"}
    assert "3 unique" in message

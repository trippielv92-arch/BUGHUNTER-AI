import socket

import httpcore
import pytest

from app.services.safe_transport import PinnedNetworkBackend


class FakeConnector:
    def __init__(self):
        self.connected = []

    def connect_tcp(self, **kwargs):
        self.connected.append(kwargs)
        return "FAKE_CONNECTION"

    def sleep(self, seconds):
        pass


def dns_record(address, family=socket.AF_INET):
    if family == socket.AF_INET6:
        sockaddr = (address, 443, 0, 0)
    else:
        sockaddr = (address, 443)

    return (family, socket.SOCK_STREAM, 6, "", sockaddr)


def test_public_dns_address_is_pinned():
    connector = FakeConnector()

    backend = PinnedNetworkBackend(
        "example.com",
        resolver=lambda *a, **k: [
            dns_record("93.184.216.34")
        ],
        connector=connector,
    )

    result = backend.connect_tcp("example.com", 443)

    assert result == "FAKE_CONNECTION"
    assert connector.connected[0]["host"] == "93.184.216.34"


def test_private_dns_address_is_rejected():
    connector = FakeConnector()

    backend = PinnedNetworkBackend(
        "example.com",
        resolver=lambda *a, **k: [
            dns_record("127.0.0.1")
        ],
        connector=connector,
    )

    with pytest.raises(httpcore.ConnectError, match="non-public"):
        backend.connect_tcp("example.com", 443)

    assert connector.connected == []


def test_mixed_public_and_private_dns_is_rejected():
    connector = FakeConnector()

    backend = PinnedNetworkBackend(
        "example.com",
        resolver=lambda *a, **k: [
            dns_record("93.184.216.34"),
            dns_record("10.0.0.5"),
        ],
        connector=connector,
    )

    with pytest.raises(httpcore.ConnectError, match="non-public"):
        backend.connect_tcp("example.com", 443)

    assert connector.connected == []


def test_hostname_mismatch_is_rejected():
    connector = FakeConnector()

    backend = PinnedNetworkBackend(
        "example.com",
        resolver=lambda *a, **k: [
            dns_record("93.184.216.34")
        ],
        connector=connector,
    )

    with pytest.raises(httpcore.ConnectError, match="hostname"):
        backend.connect_tcp("attacker.example", 443)

    assert connector.connected == []


def test_non_https_port_is_rejected():
    backend = PinnedNetworkBackend("example.com")

    with pytest.raises(httpcore.ConnectError, match="443"):
        backend.connect_tcp("example.com", 80)


def test_empty_dns_response_is_rejected():
    backend = PinnedNetworkBackend(
        "example.com",
        resolver=lambda *a, **k: [],
    )

    with pytest.raises(httpcore.ConnectError, match="no usable"):
        backend.connect_tcp("example.com", 443)


def test_public_ipv6_address_is_pinned():
    connector = FakeConnector()

    backend = PinnedNetworkBackend(
        "example.com",
        resolver=lambda *a, **k: [
            dns_record("2606:2800:220:1:248:1893:25c8:1946",
                       socket.AF_INET6)
        ],
        connector=connector,
    )

    backend.connect_tcp("example.com", 443)

    assert connector.connected[0]["host"] == (
        "2606:2800:220:1:248:1893:25c8:1946"
    )


def test_dns_is_cached_after_first_validation():
    connector = FakeConnector()
    calls = []

    def resolver(*args, **kwargs):
        calls.append(args[0])
        return [dns_record("93.184.216.34")]

    backend = PinnedNetworkBackend(
        "example.com",
        resolver=resolver,
        connector=connector,
    )

    backend.connect_tcp("example.com", 443)
    backend.connect_tcp("example.com", 443)

    assert calls == ["example.com"]
    assert len(connector.connected) == 2


def test_private_ipv4_mapped_ipv6_is_rejected():
    backend = PinnedNetworkBackend(
        "example.com",
        resolver=lambda *a, **k: [
            dns_record("::ffff:127.0.0.1", socket.AF_INET6)
        ],
        connector=FakeConnector(),
    )

    with pytest.raises(httpcore.ConnectError, match="non-public"):
        backend.connect_tcp("example.com", 443)


def test_transport_preserves_hostname_and_streams_response():
    import httpx

    from app.services.safe_transport import PinnedHTTPTransport

    class FakePool:
        def __init__(self):
            self.request = None

        def handle_request(self, request):
            self.request = request
            return httpcore.Response(
                200,
                headers=[(b"content-type", b"text/plain")],
                content=b"transport-test-ok",
            )

        def close(self):
            pass

    transport = PinnedHTTPTransport(
        "example.com",
        resolver=lambda *a, **k: [dns_record("93.184.216.34")],
        connector=FakeConnector(),
    )
    fake_pool = FakePool()
    transport.pool = fake_pool

    with httpx.Client(transport=transport) as client:
        response = client.get("https://example.com/")

    assert response.status_code == 200
    assert response.text == "transport-test-ok"
    assert fake_pool.request.url.host == b"example.com"


def test_transport_rejects_wrong_hostname():
    import httpx

    from app.services.safe_transport import PinnedHTTPTransport

    transport = PinnedHTTPTransport("example.com")

    with httpx.Client(transport=transport) as client:
        with pytest.raises(ValueError, match="outside pinned target"):
            client.get("https://attacker.example/")


def test_transport_rejects_non_get_method():
    import httpx

    from app.services.safe_transport import PinnedHTTPTransport

    transport = PinnedHTTPTransport("example.com")

    with httpx.Client(transport=transport) as client:
        with pytest.raises(ValueError, match="Only GET"):
            client.post("https://example.com/")


def test_httpx_timeout_is_forwarded_to_httpcore():
    import httpx

    from app.services.safe_transport import PinnedHTTPTransport

    class FakePool:
        request = None

        def handle_request(self, request):
            self.request = request
            return httpcore.Response(
                200,
                headers=[(b"content-type", b"text/plain")],
                content=b"ok",
            )

        def close(self):
            pass

    transport = PinnedHTTPTransport("example.com")
    fake_pool = FakePool()
    transport.pool = fake_pool

    with httpx.Client(transport=transport, timeout=3.25) as client:
        response = client.get("https://example.com/")

    assert response.status_code == 200
    timeout = fake_pool.request.extensions["timeout"]
    assert timeout["connect"] == 3.25
    assert timeout["read"] == 3.25
    assert timeout["write"] == 3.25
    assert timeout["pool"] == 3.25


def test_limited_response_stops_at_configured_byte_limit(monkeypatch):
    from contextlib import contextmanager
    from httpx import Headers
    from app.services import engine

    class FakeResponse:
        status_code = 200
        headers = Headers({"content-type": "text/plain"})

        def iter_bytes(self, chunk_size=None):
            assert chunk_size is not None
            assert chunk_size > 0
            yield b"abcd"
            yield b"efgh"

    class FakeClient:
        @contextmanager
        def stream(self, method, url):
            assert method == "GET"
            yield FakeResponse()

    monkeypatch.setattr(engine, "MAX_RESPONSE_BYTES", 5)

    result = engine._read_limited_response(
        FakeClient(),
        "https://example.com/",
    )

    assert result["body"] == b"abcde"
    assert len(result["body"]) == 5
    assert result["truncated"] is True


def test_limited_response_exact_limit_is_not_marked_truncated(monkeypatch):
    from contextlib import contextmanager
    from httpx import Headers
    from app.services import engine

    class FakeResponse:
        status_code = 200
        headers = Headers({"content-type": "text/plain"})

        def iter_bytes(self, chunk_size=None):
            assert chunk_size is not None
            yield b"abc"
            yield b"de"

    class FakeClient:
        @contextmanager
        def stream(self, method, url):
            yield FakeResponse()

    monkeypatch.setattr(engine, "MAX_RESPONSE_BYTES", 5)

    result = engine._read_limited_response(
        FakeClient(),
        "https://example.com/",
    )

    assert result["body"] == b"abcde"
    assert result["truncated"] is False


def _run_local_tls_test(tmp_path, monkeypatch, certificate_hostname):
    import http.server
    import shutil
    import socket
    import ssl
    import subprocess
    import threading

    import httpx
    from httpcore._backends.sync import SyncStream
    from app.services import safe_transport

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("OpenSSL is required for the local TLS integration test.")

    cert_file = tmp_path / "server.crt"
    key_file = tmp_path / "server.key"

    subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-keyout", str(key_file),
            "-out", str(cert_file), "-days", "1",
            "-subj", "/CN=" + certificate_hostname,
            "-addext", "subjectAltName=DNS:" + certificate_hostname,
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,digitalSignature,keyCertSign,keyEncipherment",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    observed_sni = []
    connected_addresses = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b"local-tls-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class LocalTLSConnector:
        """Test-only connector: route the pinned connection to loopback."""

        def __init__(self, port):
            self.port = port

        def connect_tcp(
            self, host, port, timeout=None,
            local_address=None, socket_options=None,
        ):
            connected_addresses.append((host, port))
            sock = socket.create_connection(
                ("127.0.0.1", self.port),
                timeout=timeout,
            )
            return SyncStream(sock)

        def sleep(self, seconds):
            threading.Event().wait(seconds)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(cert_file), str(key_file))
    server_context.set_servername_callback(
        lambda sock, name, context: observed_sni.append(name)
    )

    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), Handler
    )
    server.daemon_threads = True
    server.socket = server_context.wrap_socket(
        server.socket, server_side=True
    )

    server_thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    server_thread.start()

    try:
        client_context = ssl.create_default_context()
        client_context.load_verify_locations(cafile=str(cert_file))
        client_context.check_hostname = True
        client_context.verify_mode = ssl.CERT_REQUIRED

        monkeypatch.setattr(
            safe_transport.ssl,
            "create_default_context",
            lambda *args, **kwargs: client_context,
        )

        transport = safe_transport.PinnedHTTPTransport(
            "example.com",
            resolver=lambda *args, **kwargs: [
                dns_record("93.184.216.34")
            ],
            connector=LocalTLSConnector(server.server_port),
        )

        with httpx.Client(
            transport=transport,
            timeout=3.0,
        ) as client:
            response = client.get("https://example.com/")

        return response, observed_sni, connected_addresses

    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=3)


def test_local_tls_accepts_matching_hostname_certificate(
    tmp_path, monkeypatch
):
    response, observed_sni, connected = _run_local_tls_test(
        tmp_path,
        monkeypatch,
        "example.com",
    )

    assert response.status_code == 200
    assert response.text == "local-tls-ok"
    assert observed_sni == ["example.com"]
    assert connected == [("93.184.216.34", 443)]


def test_local_tls_rejects_wrong_hostname_certificate(
    tmp_path, monkeypatch
):
    import httpx

    with pytest.raises(httpx.ConnectError):
        _run_local_tls_test(
            tmp_path,
            monkeypatch,
            "wrong.example.com",
        )

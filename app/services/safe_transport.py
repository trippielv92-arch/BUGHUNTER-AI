"""DNS-pinned HTTPS transport for authorized assessments."""

import ipaddress
import socket
import ssl
from threading import Lock

import httpcore
import httpx
from httpx._transports.default import map_httpcore_exceptions


class PinnedNetworkBackend(httpcore.SyncBackend):
    """Connect only to validated, cached public IP addresses."""

    def __init__(self, hostname, resolver=None, connector=None):
        self.hostname = hostname.rstrip(".").lower()
        self.resolver = resolver or socket.getaddrinfo
        self.connector = connector or httpcore.SyncBackend()
        self._addresses = None
        self._lock = Lock()

    @staticmethod
    def _host_text(host):
        if isinstance(host, bytes):
            host = host.decode("ascii")
        return host.rstrip(".").lower()

    def _resolve_addresses(self):
        with self._lock:
            if self._addresses is not None:
                return self._addresses

            try:
                records = self.resolver(
                    self.hostname,
                    443,
                    type=socket.SOCK_STREAM,
                )
            except OSError as exc:
                raise httpcore.ConnectError(
                    f"DNS resolution failed for {self.hostname}"
                ) from exc

            addresses = []

            for record in records:
                family, _, _, _, sockaddr = record

                if family not in (socket.AF_INET, socket.AF_INET6):
                    raise httpcore.ConnectError(
                        "Unsupported DNS address family."
                    )

                address = sockaddr[0]

                if "%" in address:
                    raise httpcore.ConnectError(
                        "Scoped IP addresses are not permitted."
                    )

                try:
                    ip = ipaddress.ip_address(address)
                except ValueError as exc:
                    raise httpcore.ConnectError(
                        "DNS returned an invalid IP address."
                    ) from exc

                # IPv4-mapped IPv6 addresses must also be checked.
                effective_ip = (
                    ip.ipv4_mapped
                    if ip.version == 6 and ip.ipv4_mapped is not None
                    else ip
                )

                if not effective_ip.is_global:
                    raise httpcore.ConnectError(
                        f"DNS returned a non-public address: {address}"
                    )

                if family == socket.AF_INET and ip.version != 4:
                    raise httpcore.ConnectError("Invalid IPv4 DNS record.")

                if family == socket.AF_INET6 and ip.version != 6:
                    raise httpcore.ConnectError("Invalid IPv6 DNS record.")

                if address not in addresses:
                    addresses.append(address)

            if not addresses:
                raise httpcore.ConnectError(
                    "DNS returned no usable public addresses."
                )

            self._addresses = tuple(addresses)
            return self._addresses

    def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        if self._host_text(host) != self.hostname:
            raise httpcore.ConnectError(
                "Connection hostname differs from pinned target."
            )

        if port != 443:
            raise httpcore.ConnectError(
                "Only HTTPS port 443 is permitted."
            )

        failures = []

        for address in self._resolve_addresses():
            try:
                return self.connector.connect_tcp(
                    host=address,
                    port=443,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                failures.append(exc)

        if failures:
            raise failures[-1]

        raise httpcore.ConnectError("No validated connection address.")

    def connect_unix_socket(self, *args, **kwargs):
        raise httpcore.ConnectError("Unix sockets are not permitted.")

    def sleep(self, seconds):
        return self.connector.sleep(seconds)


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, stream):
        self.stream = stream

    def __iter__(self):
        with map_httpcore_exceptions():
            yield from self.stream

    def close(self):
        close = getattr(self.stream, "close", None)
        if callable(close):
            close()


class PinnedHTTPTransport(httpx.BaseTransport):
    """GET-only HTTPS transport preserving original TLS hostname."""

    def __init__(self, hostname, resolver=None, connector=None):
        if not hostname:
            raise ValueError("A target hostname is required.")

        self.hostname = hostname.rstrip(".").lower()

        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        self.backend = PinnedNetworkBackend(
            self.hostname,
            resolver=resolver,
            connector=connector,
        )

        self.pool = httpcore.ConnectionPool(
            ssl_context=context,
            network_backend=self.backend,
            max_connections=1,
            max_keepalive_connections=1,
            keepalive_expiry=5.0,
            http1=True,
            http2=False,
            retries=0,
        )

    def validate_dns(self):
        """Resolve and validate the target before the first HTTP request."""
        return self.backend._resolve_addresses()

    def handle_request(self, request):
        if request.method.upper() != "GET":
            raise ValueError("Only GET requests are permitted.")

        if request.url.scheme != "https":
            raise ValueError("HTTPS is required.")

        if request.url.host.rstrip(".").lower() != self.hostname:
            raise ValueError("Request hostname is outside pinned target.")

        if request.url.port not in (None, 443):
            raise ValueError("Only HTTPS port 443 is permitted.")

        core_request = httpcore.Request(
            method="GET",
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=443,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=b"",
            extensions=request.extensions,
        )

        with map_httpcore_exceptions():
            response = self.pool.handle_request(core_request)

        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_ResponseStream(response.stream),
            extensions=response.extensions,
            request=request,
        )

    def close(self):
        self.pool.close()

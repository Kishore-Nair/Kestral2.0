import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import HTTPException
from queue import Empty, SimpleQueue
from threading import Thread
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from packaging.version import InvalidVersion, Version

from app.ai.versions import parse_semver

NPM = "registry.npmjs.org"
PYPI = "pypi.org"
NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
PYPI_NAME = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?", re.ASCII)


def canonical_name(ecosystem: str, name: str) -> str | None:
    if len(name) > 214:
        return None
    if ecosystem == "npm" and NPM_NAME.fullmatch(name):
        return name
    if ecosystem == "pypi" and PYPI_NAME.fullmatch(name):
        return re.sub(r"[-_.]+", "-", name).lower()
    return None


def exact_version(ecosystem: str, value: str | None) -> str | None:
    if not value or len(value) > 80 or value.strip() != value:
        return None
    if ecosystem == "npm":
        return value if parse_semver(value) is not None else None
    if ecosystem == "pypi":
        try:
            return str(Version(value))
        except InvalidVersion:
            return None
    return None


def stable_identity(ecosystem: str, value: str) -> str | None:
    if ecosystem == "npm":
        parsed = parse_semver(value)
        if parsed and not parsed[3]:
            return ".".join(map(str, parsed[:3]))
    elif ecosystem == "pypi":
        version = Version(value)
        if not (version.is_prerelease or version.is_devrelease or version.local):
            release = list(version.release)
            while len(release) > 1 and release[-1] == 0:
                release.pop()
            return f"{version.epoch}!{release!s}:{version.post}"
    return None


class RegistryError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RegistryError("redirect_rejected")


def metadata_url(ecosystem: str, name: str) -> str:
    encoded = quote(name, safe="")
    return f"https://{NPM}/{encoded}" if ecosystem == "npm" else f"https://{PYPI}/pypi/{encoded}/json"


def _valid_metadata_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        if parsed.netloc == NPM:
            ecosystem, encoded = "npm", parsed.path.removeprefix("/")
        elif parsed.netloc == PYPI and parsed.path.startswith("/pypi/") and parsed.path.endswith(
            "/json"
        ):
            ecosystem, encoded = "pypi", parsed.path[len("/pypi/"):-len("/json")]
        else:
            return False
        name = unquote(encoded)
        return canonical_name(ecosystem, name) == name and metadata_url(ecosystem, name) == url
    except ValueError:
        return False


def fetch_metadata(url: str, timeout: float, max_bytes: int) -> bytes:
    if not _valid_metadata_url(url):
        raise RegistryError("invalid_registry_url")
    opener = build_opener(ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + timeout
    request = Request(url, headers={"Accept": "application/json", "Accept-Encoding": "identity"})
    with opener.open(request, timeout=timeout) as response:
        encoding = response.headers.get("Content-Encoding", "identity")
        length = response.headers.get("Content-Length")
        if response.status != 200 or encoding.lower() != "identity":
            raise RegistryError("malformed_metadata")
        if length is not None and int(length) > max_bytes:
            raise RegistryError("oversize")
        result = bytearray()
        while len(result) <= max_bytes:
            if time.monotonic() >= deadline:
                raise TimeoutError
            chunk = response.read1(min(65536, max_bytes + 1 - len(result)))
            if not chunk:
                return bytes(result)
            result.extend(chunk)
    raise RegistryError("oversize")


def bounded_fetch(url: str, timeout: float, max_bytes: int) -> bytes:
    # DNS, TLS, and HTTP header reads can outlive individual socket deadlines.
    # The worker only receives public GET parameters and cannot write artifacts.
    results: SimpleQueue = SimpleQueue()

    def run():
        try:
            results.put(fetch_metadata(url, timeout, max_bytes))
        except Exception as error:
            results.put(error)

    Thread(target=run, daemon=True).start()
    try:
        result = results.get(timeout=timeout)
    except Empty:
        raise TimeoutError from None
    if isinstance(result, Exception):
        raise result
    return result


@dataclass(frozen=True)
class Budget:
    packages: int = 20
    requests: int = 25
    timeout: float = 5
    seconds: float = 30
    response_bytes: int = 4 * 1024 * 1024

    def __post_init__(self):
        if not (
            1 <= self.packages <= 40 and 1 <= self.requests <= 50
            and 0 < self.timeout <= 10 and 0 < self.seconds <= 60
            and 1024 <= self.response_bytes <= 8 * 1024 * 1024
        ):
            raise ValueError("Registry budget exceeds hard caps")


DEFAULT_BUDGET = Budget()


@dataclass(frozen=True)
class Snapshot:
    status: str
    url: str | None = None
    observed_at: datetime | None = None
    sha256: str | None = None
    data: dict | None = None


class Registry:
    def __init__(
        self, allowed: set[tuple[str, str]], *, enabled: bool = False,
        budget: Budget = DEFAULT_BUDGET, fetch=None, clock=time.monotonic,
        now=lambda: datetime.now(UTC),
    ):
        self.allowed = allowed
        self.enabled = enabled
        self.budget = budget
        self.fetch = fetch or bounded_fetch
        self.source = "live_registry" if fetch is None else "injected_fixture"
        self.clock = clock
        self.now = now
        self.deadline = clock() + budget.seconds
        self.requests = 0
        self.cache: dict[tuple[str, str], Snapshot] = {}

    def get(self, ecosystem: str, name: str) -> Snapshot:
        key = ecosystem, name
        if canonical_name(ecosystem, name) != name:
            return Snapshot("unsupported_or_invalid_identity")
        if not self.enabled:
            return Snapshot("network_disabled")
        if key not in self.allowed:
            return Snapshot("not_authorized")
        if key in self.cache:
            return self.cache[key]
        remaining = self.deadline - self.clock()
        if (
            remaining <= 0 or self.requests >= self.budget.requests
            or len(self.cache) >= self.budget.packages
        ):
            return Snapshot("budget_skipped")
        url = metadata_url(ecosystem, name)
        self.requests += 1
        result = self._load(url, min(remaining, self.budget.timeout))
        self.cache[key] = result
        return result

    def _load(self, url: str, timeout: float) -> Snapshot:
        try:
            raw = self.fetch(url, timeout, self.budget.response_bytes)
            if len(raw) > self.budget.response_bytes:
                raise RegistryError("oversize")
            if self.clock() >= self.deadline:
                raise TimeoutError
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise RegistryError("malformed_metadata")
            return Snapshot("ok", url, self.now(), hashlib.sha256(raw).hexdigest(), data)
        except HTTPError as error:
            error.close()
            status = {404: "not_found", 429: "rate_limited"}.get(error.code, "http_error")
        except URLError as error:
            status = "timeout" if isinstance(error.reason, TimeoutError) else "network_error"
        except TimeoutError:
            status = "timeout"
        except RegistryError as error:
            status = str(error) if str(error) in {"oversize", "redirect_rejected"} else (
                "malformed_metadata"
            )
        except (ValueError, RecursionError):
            status = "malformed_metadata"
        except (OSError, HTTPException):
            status = "network_error"
        return Snapshot(status, url, self.now())

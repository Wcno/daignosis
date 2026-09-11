from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sentinel_dns.clickhouse import assert_local_url


class WazuhWebhook:
    def __init__(self, url: str) -> None:
        assert_local_url(url)
        self.url = url

    def deliver(self, alert: dict) -> bool:
        request = Request(
            self.url,
            data=json.dumps(alert, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=2) as response:
                return 200 <= response.status < 300
        except (HTTPError, URLError, OSError, TimeoutError, PermissionError):
            return False

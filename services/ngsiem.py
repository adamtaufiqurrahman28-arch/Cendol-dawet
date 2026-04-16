from __future__ import annotations

import time
from typing import Any

from utils.parsing import (
    extract_rows,
    extract_search_id,
    extract_status_text,
    is_terminal_status,
    response_error_text,
)


class NGSIEMService:
    def __init__(self, client: Any, default_repository: str, poll_interval: float, timeout_seconds: int) -> None:
        self.client = client
        self.default_repository = default_repository
        self.poll_interval = poll_interval
        self.timeout_seconds = timeout_seconds

    def run_query(self, query: str, start: str, repository: str | None = None) -> dict[str, Any]:
        repo = repository or self.default_repository
        payload = {
            "isLive": False,
            "start": start,
            "queryString": query,
        }
        start_resp = self.client.start_search(repository=repo, search=payload)
        if start_resp.get("status_code", 500) >= 300:
            raise RuntimeError(f"StartSearch gagal: {response_error_text(start_resp)}")

        search_id = extract_search_id(start_resp)
        if not search_id:
            raise RuntimeError("Search ID tidak ditemukan pada response StartSearch.")

        deadline = time.time() + self.timeout_seconds
        latest_response = start_resp
        latest_status = "UNKNOWN"
        rows: list[dict[str, Any]] = []

        while time.time() < deadline:
            status_resp = self.client.get_search_status(repository=repo, search_id=search_id)
            latest_response = status_resp
            if status_resp.get("status_code", 500) >= 300:
                raise RuntimeError(f"GetSearchStatus gagal: {response_error_text(status_resp)}")

            latest_status = extract_status_text(status_resp)
            rows = extract_rows(status_resp)
            if is_terminal_status(latest_status):
                break
            time.sleep(self.poll_interval)

        return {
            "repository": repo,
            "search_id": search_id,
            "status": latest_status,
            "rows": rows,
            "raw": latest_response,
        }

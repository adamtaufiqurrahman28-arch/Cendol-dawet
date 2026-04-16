from __future__ import annotations

from dataclasses import dataclass
from mimetypes import guess_type
from pathlib import Path
from typing import Any

from utils.parsing import response_error_text


@dataclass(slots=True)
class RTRAsset:
    id: str
    name: str
    kind: str


class RTRService:
    def __init__(self, rtr_client: Any, rtr_admin_client: Any, timeout_seconds: int, queue_offline: bool) -> None:
        self.rtr_client = rtr_client
        self.rtr_admin_client = rtr_admin_client
        self.timeout_seconds = timeout_seconds
        self.queue_offline = queue_offline

    def list_put_files(self) -> list[RTRAsset]:
        resp = self.rtr_admin_client.list_put_files(limit=100, sort="name.asc")
        if resp.get("status_code", 500) >= 300:
            raise RuntimeError(f"Gagal list put files: {response_error_text(resp)}")
        ids = self._extract_list(resp)
        assets: list[RTRAsset] = []
        for item in ids:
            if isinstance(item, dict):
                asset_id = str(item.get("id", ""))
                name = str(item.get("name", asset_id))
            else:
                asset_id = str(item)
                name = asset_id
            if asset_id:
                assets.append(RTRAsset(id=asset_id, name=name, kind="put-file"))
        return assets

    def list_scripts(self) -> list[RTRAsset]:
        resp = self.rtr_admin_client.list_scripts(limit=100, sort="name.asc")
        if resp.get("status_code", 500) >= 300:
            raise RuntimeError(f"Gagal list scripts: {response_error_text(resp)}")
        ids = self._extract_list(resp)
        assets: list[RTRAsset] = []
        for item in ids:
            if isinstance(item, dict):
                asset_id = str(item.get("id", ""))
                name = str(item.get("name", asset_id))
            else:
                asset_id = str(item)
                name = asset_id
            if asset_id:
                assets.append(RTRAsset(id=asset_id, name=name, kind="script"))
        return assets

    def upload_put_file(self, local_path: str, description: str = "Uploaded from cs_blue_cli") -> dict[str, Any]:
        file_path = Path(local_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File tidak ditemukan: {file_path}")

        mime_type = guess_type(file_path.name)[0] or "application/octet-stream"
        file_bytes = file_path.read_bytes()
        files = [("file", (file_path.name, file_bytes, mime_type))]
        resp = self.rtr_admin_client.create_put_files_v2(
            files=files,
            description=description,
            name=file_path.name,
            comments_for_audit_log="Upload from cs_blue_cli",
        )
        if resp.get("status_code", 500) >= 300:
            raise RuntimeError(f"Upload put-file gagal: {response_error_text(resp)}")
        return resp

    def batch_init(self, host_ids: list[str]) -> dict[str, Any]:
        resp = self.rtr_client.batch_init_sessions(
            host_ids=host_ids,
            queue_offline=self.queue_offline,
            timeout=self.timeout_seconds,
            timeout_duration=f"{self.timeout_seconds}s",
        )
        if resp.get("status_code", 500) >= 300:
            raise RuntimeError(f"Batch init gagal: {response_error_text(resp)}")
        return resp

    def batch_put(self, batch_id: str, host_ids: list[str], cloud_filename: str) -> dict[str, Any]:
        cmd = f"put '{cloud_filename}'"
        resp = self.rtr_client.batch_active_responder_command(
            base_command="put",
            batch_id=batch_id,
            command_string=cmd,
            optional_hosts=host_ids,
            persist_all=self.queue_offline,
            timeout=self.timeout_seconds,
            timeout_duration=f"{self.timeout_seconds}s",
        )
        if resp.get("status_code", 500) >= 300:
            raise RuntimeError(f"Batch put gagal: {response_error_text(resp)}")
        return resp

    def batch_admin_command(self, batch_id: str, host_ids: list[str], base_command: str, command_string: str) -> dict[str, Any]:
        resp = self.rtr_admin_client.batch_admin_command(
            base_command=base_command,
            batch_id=batch_id,
            command_string=command_string,
            optional_hosts=host_ids,
            timeout=self.timeout_seconds,
            timeout_duration=f"{self.timeout_seconds}s",
        )
        if resp.get("status_code", 500) >= 300:
            raise RuntimeError(f"Batch admin command gagal: {response_error_text(resp)}")
        return resp

    @staticmethod
    def extract_batch_id(response: dict[str, Any]) -> str | None:
        for path in [
            ("body", "resources", "batch_id"),
            ("body", "batch_id"),
            ("resources", "batch_id"),
        ]:
            value = RTRService._safe_walk(response, path)
            if isinstance(value, str) and value:
                return value
        resources = RTRService._safe_walk(response, ("body", "resources"))
        if isinstance(resources, list):
            for item in resources:
                if isinstance(item, dict):
                    batch_id = item.get("batch_id") or item.get("id")
                    if batch_id:
                        return str(batch_id)
        return None

    @staticmethod
    def _safe_walk(obj: Any, path: tuple[str, ...]) -> Any:
        current = obj
        for key in path:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    @staticmethod
    def _extract_list(response: dict[str, Any]) -> list[Any]:
        for path in [
            ("body", "resources"),
            ("resources",),
        ]:
            value = RTRService._safe_walk(response, path)
            if isinstance(value, list):
                return value
        return []

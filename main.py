#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any

from rich.prompt import Prompt

from config import ConfigurationError, load_settings
from queries import PRESET_QUERIES
from services.falcon import FalconClients
from services.ngsiem import NGSIEMService
from services.rtr import RTRService
from ui.console import banner, console, error, info, save_json, show_json, show_query, show_table, success, warn
from ui.menus import ask_lookback, ask_repository, ask_yes_no, main_menu, preset_menu, read_multiline_query
from utils.parsing import pick_columns


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CrowdStrike Blue Team CLI")
    parser.add_argument("--env-file", default=".env", help="Path ke file .env")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    banner()

    try:
        settings = load_settings(args.env_file)
    except ConfigurationError as exc:
        error(str(exc))
        return 1

    clients = FalconClients(settings)
    ngsiem = NGSIEMService(
        client=clients.ngsiem,
        default_repository=settings.default_repository,
        poll_interval=settings.ngsiem_poll_interval,
        timeout_seconds=settings.ngsiem_timeout_seconds,
    )
    rtr = RTRService(
        rtr_client=clients.rtr,
        rtr_admin_client=clients.rtr_admin,
        timeout_seconds=settings.rtr_timeout_seconds,
        queue_offline=settings.rtr_queue_offline,
    )

    while True:
        try:
            choice = main_menu()
            if choice == "1":
                handle_preset_queries(ngsiem, settings.default_repository)
            elif choice == "2":
                handle_manual_query(ngsiem, settings.default_repository, settings.default_lookback)
            elif choice == "3":
                handle_llm_dummy()
            elif choice == "4":
                handle_bulk_rtr(rtr)
            elif choice == "5":
                handle_list_rtr_assets(rtr)
            elif choice == "0":
                success("Bye. Stay sharp.")
                return 0
        except KeyboardInterrupt:
            warn("Dibatalkan oleh user.")
        except Exception as exc:  # noqa: BLE001
            error(str(exc))


def handle_preset_queries(ngsiem: NGSIEMService, default_repository: str) -> None:
    choice = preset_menu()
    if choice == "0":
        return

    preset = PRESET_QUERIES[choice]
    lookback = ask_lookback(preset["lookback"])
    repository = ask_repository(default_repository)
    show_query(f"Preset: {preset['name']}", preset["query"])
    result = ngsiem.run_query(query=preset["query"], start=lookback, repository=repository)
    render_hunt_result(result, default_name=preset["name"].replace(" ", "_").lower())


def handle_manual_query(ngsiem: NGSIEMService, default_repository: str, default_lookback: str) -> None:
    repository = ask_repository(default_repository)
    lookback = ask_lookback(default_lookback)
    query = read_multiline_query()
    if not query:
        warn("Query kosong.")
        return
    show_query("Manual Query", query)
    result = ngsiem.run_query(query=query, start=lookback, repository=repository)
    render_hunt_result(result, default_name="manual_query")


def handle_llm_dummy() -> None:
    warn("Menu ini masih dummy.")
    console.print(
        "[bold]Investigation with LLM[/bold]\n"
        "- Nanti bisa dipakai untuk merangkum output query\n"
        "- Nanti bisa dipakai untuk buat triage narrative\n"
        "- Nanti bisa dipakai untuk suggest next-step hunting\n"
    )


def handle_list_rtr_assets(rtr: RTRService) -> None:
    put_files = rtr.list_put_files()
    scripts = rtr.list_scripts()

    if put_files:
        rows = [{"kind": item.kind, "id": item.id, "name": item.name} for item in put_files]
        show_table(rows, ["kind", "id", "name"], title="RTR Put Files")
    else:
        warn("Belum ada RTR put-file yang terdaftar.")

    if scripts:
        rows = [{"kind": item.kind, "id": item.id, "name": item.name} for item in scripts]
        show_table(rows, ["kind", "id", "name"], title="RTR Scripts")
    else:
        warn("Belum ada RTR script yang terdaftar.")


def handle_bulk_rtr(rtr: RTRService) -> None:
    console.print("\n[bold]Bulk RTR Put and Run[/bold]")
    host_ids_raw = Prompt.ask("Masukkan host AID (pisahkan dengan koma)")
    host_ids = [item.strip() for item in host_ids_raw.split(",") if item.strip()]
    if not host_ids:
        warn("Host ID kosong.")
        return

    local_path = Prompt.ask("Path file lokal untuk di-upload ke RTR Cloud")
    description = Prompt.ask("Deskripsi upload", default="Uploaded from cs_blue_cli")
    upload_resp = rtr.upload_put_file(local_path=local_path, description=description)
    success("Put-file berhasil di-upload ke RTR Cloud.")

    init_resp = rtr.batch_init(host_ids)
    batch_id = rtr.extract_batch_id(init_resp)
    if not batch_id:
        raise RuntimeError("Batch ID tidak ditemukan setelah batch_init_sessions.")
    success(f"Batch session siap. batch_id={batch_id}")

    cloud_filename = Path(local_path).name
    put_resp = rtr.batch_put(batch_id=batch_id, host_ids=host_ids, cloud_filename=cloud_filename)
    success(f"Perintah put dikirim untuk file: {cloud_filename}")
    show_json("RTR Put Response", put_resp)

    if ask_yes_no("Kirim command lanjutan setelah put?"):
        base_command = Prompt.ask("Base command", default="runscript")
        command_string = Prompt.ask(
            "Command string lengkap",
            default=f"runscript -CloudFile='{cloud_filename}' -Timeout=600",
        )
        follow_resp = rtr.batch_admin_command(
            batch_id=batch_id,
            host_ids=host_ids,
            base_command=base_command,
            command_string=command_string,
        )
        success("Command lanjutan berhasil dikirim.")
        show_json("RTR Follow-up Response", follow_resp)


def render_hunt_result(result: dict[str, Any], default_name: str) -> None:
    rows = result["rows"]
    status = result["status"]
    search_id = result["search_id"]
    info(f"search_id={search_id} | status={status} | rows={len(rows)}")

    if rows:
        columns = pick_columns(rows)
        show_table(rows, columns, title=f"NGSIEM Results ({len(rows)} rows)")
    else:
        warn("Tidak ada row tabel yang berhasil diekstrak. Menampilkan raw JSON.")
        show_json("Raw NGSIEM Response", result["raw"])

    if ask_yes_no("Simpan raw JSON?"):
        out_path = Prompt.ask("Nama file JSON", default=f"{default_name}.json")
        save_json(out_path, result["raw"])

    if rows and ask_yes_no("Export row hasil ke CSV?"):
        csv_path = Prompt.ask("Nama file CSV", default=f"{default_name}.csv")
        export_csv(csv_path, rows)


def export_csv(path: str, rows: list[dict[str, Any]]) -> None:
    file_path = Path(path)
    columns = sorted({key for row in rows for key in row.keys()})
    with file_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    success(f"CSV disimpan ke {file_path}")


if __name__ == "__main__":
    raise SystemExit(main())

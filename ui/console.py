from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

console = Console()


def banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]CrowdStrike Blue Team CLI[/bold cyan]\n"
            "NGSIEM hunting • RTR operations • Blue team style terminal UX by Seraphim Blue Team",
            border_style="cyan",
        )
    )


def info(message: str) -> None:
    console.print(f"[bold cyan][*][/bold cyan] {message}")


def success(message: str) -> None:
    console.print(f"[bold green][+][/bold green] {message}")


def warn(message: str) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {message}")


def error(message: str) -> None:
    console.print(f"[bold red][-][/bold red] {message}")


def show_json(title: str, payload: dict[str, Any]) -> None:
    console.print(Panel.fit(Syntax(json.dumps(payload, indent=2, ensure_ascii=False), "json", word_wrap=True), title=title))


def show_query(title: str, query: str) -> None:
    console.print(Panel(Syntax(query, "sql", word_wrap=True), title=title, border_style="blue"))


def show_table(rows: list[dict[str, Any]], columns: list[str], title: str = "Results") -> None:
    if not rows:
        warn("Tidak ada row yang bisa ditampilkan dalam tabel.")
        return

    table = Table(title=title, box=box.MINIMAL_DOUBLE_HEAD, show_lines=False)
    for column in columns:
        table.add_column(column, overflow="fold")

    for row in rows:
        table.add_row(*[_format_cell(row.get(column, "")) for column in columns])

    console.print(table)


def save_json(path: str | Path, payload: dict[str, Any]) -> None:
    file_path = Path(path)
    file_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    success(f"Raw JSON disimpan ke {file_path}")


def _format_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    if len(text) > 180:
        return text[:177] + "..."
    return text

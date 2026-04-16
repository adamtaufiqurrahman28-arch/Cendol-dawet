from __future__ import annotations

from rich.prompt import Confirm, Prompt

from queries import PRESET_QUERIES
from ui.console import console


def main_menu() -> str:
    console.print("\n[bold]Main Menu[/bold]")
    console.print("[cyan]1[/cyan]. Preset Hunting Queries")
    console.print("[cyan]2[/cyan]. Manual NGSIEM Query")
    console.print("[cyan]3[/cyan]. Investigation with LLM (BETA Release)")
    console.print("[cyan]4[/cyan]. Bulk RTR Put and Run")
    console.print("[cyan]5[/cyan]. List RTR Cloud Assets")
    console.print("[cyan]0[/cyan]. Exit")
    return Prompt.ask("Pilih menu", choices=["1", "2", "3", "4", "5", "0"], default="1")


def preset_menu() -> str:
    console.print("\n[bold]Preset Hunting Queries[/bold]")
    for key, item in PRESET_QUERIES.items():
        console.print(f"[cyan]{key}[/cyan]. {item['name']}  [dim](lookback default: {item['lookback']})[/dim]")
    console.print("[cyan]0[/cyan]. Kembali")
    choices = list(PRESET_QUERIES.keys()) + ["0"]
    return Prompt.ask("Pilih preset", choices=choices, default="1")


def read_multiline_query() -> str:
    console.print("Paste query Anda. Ketik [bold cyan]END[/bold cyan] pada baris baru untuk selesai.")
    lines: list[str] = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    return "\n".join(lines).strip()


def ask_lookback(default_value: str) -> str:
    return Prompt.ask("Lookback", default=default_value).strip()


def ask_repository(default_value: str) -> str:
    return Prompt.ask("Repository", default=default_value).strip()


def ask_yes_no(message: str, default: bool = False) -> bool:
    return Confirm.ask(message, default=default)

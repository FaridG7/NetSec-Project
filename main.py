import os
import time
from pathlib import Path
from rich.console import Console
from rich.progress import Progress
import questionary

from modules.exceptions import ConflictError
from modules.login import login
from actions import actions

console = Console()

def select_action(actions):
    return questionary.select(
        "What do you want to do?",
        choices=actions
    ).ask()

def main():
    console.print("[bold yellow]📅 MailBox(My Network Security Class Project)[/bold yellow]")
    login()
    action = select_action(actions)


if __name__ == "__main__":
    main()

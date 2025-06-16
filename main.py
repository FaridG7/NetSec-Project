import os
import time
from pathlib import Path
from rich.console import Console
from rich.progress import Progress
import questionary

from modules.exceptions import ConflictError
console = Console()

def select_action(actions):
    return questionary.select(
        "What do you want to do?",
        choices=actions
    ).ask()

def main():
    console.print("[bold yellow]📅 MailBox(My Network Security Class Project)[/bold yellow]")

    task_sets = list_task_sets()
    if not task_sets:
        console.print("[red]No task sets found! Put JSON files in the 'task_sets/' folder.[/red]")
        return

    task_file = select_task_set(task_sets)
    scheduler_name = select_scheduler()

    with Progress() as progress:
        load_task = progress.add_task("[cyan]Loading tasks...", total=1)
        time.sleep(0.5)
        tasks = load_tasks(Path("tasks.d") / task_file)
        progress.update(load_task, advance=1)

        # Add validation step
        validate_task = progress.add_task("[yellow]Validating task set...", total=1)
        time.sleep(0.5)
        is_valid, message = validate_task_set(tasks, scheduler_name)
        progress.update(validate_task, advance=1)

        if not is_valid:
            console.print(f"\n[bold red]❌ Task set validation failed![/bold red]")
            console.print(f"[red]{message}[/red]")
            return

        console.print(f"\n[bold green]✓ Task set validation passed![/bold green]")
        console.print(f"[green]{message}[/green]")

        run_task = progress.add_task(f"[green]Running {scheduler_name} scheduler...", total=1)
        time.sleep(0.5)
        timeline = schedulers[scheduler_name](tasks, num_cores=3)
        progress.update(run_task, advance=1)

    console.print(f"\n[bold green]✅ Done! Showing Gantt chart for {scheduler_name}[/bold green]")
    plot_gantt(f"{scheduler_name}", timeline)

if __name__ == "__main__":
    main()

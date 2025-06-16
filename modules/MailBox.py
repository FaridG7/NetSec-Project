import questionary
from typing import TypedDict
from rich.console import Console
from rich.progress import Progress

from modules.CreateNewRoom import CreateNewRoom
from modules.LoadOptions import LoadOptions
from modules.LoadUsers import LoadUsers
from modules.Login import Login
from modules.Register import Register
from modules.SafeUtils import SafeUtils
from modules.exceptions import LoginFailed

class User(TypedDict):
    username: str
    password: str
    salt: str
    public_key: str

class MailBox(LoadOptions, LoadUsers, Login, Register, SafeUtils, CreateNewRoom):
    console: Console
    user: User | None
    users: list[User]
    options: dict[str, str]
    cached_private_key: str

    def __init__(self):
        self.options = self.load_options()
        self.user = None
        self.users = self.laod_users()
        self.console = Console()

    def run(self)->None:
        while True:
            if self.user:
                self.logged_in_shell()
            else:
                self.anonymous_shell()

    def prompt_user(message:str, choices: list[str]):
        return questionary.select(
            f"{message}",
            choices=choices
        ).ask()
    
    def prompt_user_for_an_action(self,actions:list[str]):
        return self.prompt_user("Choose an Action", actions)
    
    def anonymous_shell(self)->None:
        actions = ["exit", "login","register"]
        action_map = {
            "exit": self.handle_exit,
            "login": self.handle_login,
            "register": self.handle_register
        }
        action = self.prompt_user_for_an_action(actions)
        match action:
            case "exit":
                exit(0)
            case "login":
                pass
            case "register":
                pass
    
    def login_shell(self)->None:
        username = self.console.input("[bold yellow]Username[/bold yellow][bold orange]:[/bold orange] ")
        password = self.console.input("[bold yellow]Password[/bold yellow][bold orange]:[/bold orange]  ")
        try:
            self.user = login(self.users, username, password)
            self.console.print("[bold green]Login Successful[/bold green]")
        except LoginFailed as e:
            self.console.print(f"[bold red]{e.message}[/bold red]")

    def register_shell()->None:
        pass

    def logged_in_shell(self)->None:
        actions = ["Send a message", "Inbox", "Create a new chat room", "Change password", "Logout"]
        action = self.prompt_user_for_an_action(actions)
        match action:
            case "Send a message":
                pass
            case "Inbox":
                pass
            case "Create a new chat room":
                pass
            case "Change password":
                pass
            case "Logout":
                self.logout()

    def logout(self)->None:
        self.user = None
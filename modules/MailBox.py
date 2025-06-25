import questionary
import time
from rich.console import Console
from rich.progress import Progress
from rich.prompt import Prompt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import UnsupportedAlgorithm, InvalidKey
from modules.MessageHandler import MessageHandler
from modules.LoadOptions import LoadOptions
from modules.LoadUsers import LoadUsers
from modules.Login import Login
from modules.Register import Register
from modules.Safe import SafeHandler
from modules.User import User
from modules.exceptions import BadInput, ConflictError, LoginFailed, PrivateKeyFileNotFound

class MailBox(LoadOptions, LoadUsers, Login, Register, SafeHandler, MessageHandler):
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
        self.console.clear()
        self.console.print("[bold cyan]MailBox(My Network Security Class Project)")
        while True:
            if self.user:
                self.logged_in_shell()
            else:
                self.login_shell()

    def prompt_user(self, message:str, choices: list[str])->str:
        self.console.clear()
        return questionary.select(
            f"{message}",
            choices=choices
        ).ask()
    
    def prompt_user_for_an_action(self, actions:list[str])->str:
        return self.prompt_user("Choose an Action", actions)
    
    def pause_console(self, presses=3):
        for i in range(presses):
            Prompt.ask(f"[bold yellow]Press Enter ({i+1}/{presses}) to continue[/bold yellow]", default="", show_default=False)

    def exit_shell(self):
        self.console.print("[cyan]Bye👋")
        exit(0)

    def is_valid_private_key(self, private_key:str):
        try:
            private_key = serialization.load_pem_private_key(
                private_key.encode(),
                password=None,
            )
            if isinstance(private_key, rsa.RSAPrivateKey):
                return private_key.key_size == 1024
            return False
        except (ValueError, UnsupportedAlgorithm, InvalidKey):
            return False

    def login_shell(self)->None:
        username = self.console.input("[bold yellow]Enter Username[/bold yellow][bold orange](enter 0 to abort):[/bold orange] ")
        if username == '0':
            return
        with Progress() as progress:
            login_progress = progress.add_task("[cyan]Loggining in...", total=200)
            try:
                user = self.login(self.users, username, password)
                
                for i in range(100):
                    time.sleep(0.01)
                    progress.update(login_progress, advance=1)
                self.console.print("[green]Login Successful[/green]")

                password = self.console.input("[bold yellow]Enter Password[/bold yellow][bold orange](enter 0 to abort):[/bold orange]  ")
                if password == '0':
                    return

                self.cached_private_key = self.load_private_key(self.user["username"], self.user['password'], bytes.fromhex(self.user["salt"]))

                for i in range(100):
                    time.sleep(0.01)
                    progress.update(login_progress, advance=1)

                if self.cached_private_key:
                    self.user = user
                    self.console.print("[green]Locally Saved Private Key Stored[/green]")
                else:
                    self.console.print("[yellow]Locally Saved Private Key Not Found[/yellow]")
                    while True:
                        private_key = self.console.input("[bold]Please Enter Your Private Key(in PEM format)[orange]:[/orange][/bold]")
                        if private_key == '0':

                            return
                        elif self.is_valid_private_key(private_key):
                            self.cached_private_key = private_key
                            break
                        self.console.print("[yellow]Your Private Key doesn't have a valid PEM format.[/yellow]")
                        
            except LoginFailed as e:
                progress.stop()
                self.console.print(f"[bold red]{e.message}[/bold red]")
            except PrivateKeyFileNotFound as e:
                progress.stop()
                self.console.print(f"[bold red]{e.message}[/bold red]")

    def register_shell(self)->None:
        while True:
            username = self.console.input("[bold yellow]Enter Username[/bold yellow][bold orange](enter 0 to abort):[/bold orange] ")
            if username == '0':
                return
            elif not self.is_duplicate_user_name(self.users, username):
                break
            self.console.print(f"[bold yellow]'{username}' already exists[/bold yellow]")
        while True:
            password = self.console.input("[bold yellow]Enter Password(between 8 to 16 characters with standard format)[/bold yellow][bold orange](enter 0 to abort):[/bold orange] ")
            if password == '0':
                return
            elif self.is_valid_password_format(password):
                break
            self.console.print(f"[bold yellow]Please enter a standard password[/bold yellow]")
        try:
            with Progress() as progress:
                register_progress = progress.add_task("[cyan]Register Process started...", total=100)

                for i in range(100):
                    time.sleep(0.02)
                    progress.update(register_progress, advance=1)

                result = self.register_user(self.users, username, password)

                self.user = result['user']
                self.cached_private_key = result['private_key']

            self.console.print("[green]Register Successful[/green]")
            self.console.print("[yellow]Your generated private key:[/yellow]")
            self.console.print(result['private_key'])
            self.console.print("[bold yellow]Store it somewhere safe or your account will be useless without it![bold yellow]")

            self.pause_console()

            self.store_private_key_shell()
        except ConflictError as e:
            self.console.print(f"[bold red]{e.message}[/bold red]")
        except BadInput as e:
            self.console.print(f"[bold red]{e.message}[/bold red]")
    
    def store_private_key_shell(self)->None:
        action_map = {
            "Yes": lambda: self.store_private_key(self.user['username'], self.user['password'], bytes.fromhex(self.user["salt"]), self.cached_private_key),
            "No": None,
        }
        self.console.print("""[bold yellow]TERMS & CONDITIONS[/bold yellow]
                           [yellow]the method we use to store your private key locally is using AES encryption and using your password as the key.
                           we use for confort but it is considered as a security risk and we don't recommand it. use at [bold]YOUR OWN[/bold] risk[/yellow]""")
        confirm = questionary.confirm("Do you want to store you private key LOCALLY?")
        if confirm:
            with Progress() as progress:
                storing_progress = progress.add_task("[cyan]Storing the key...", total=1)
                time.sleep(0.5)
                action_map[confirm]()
                progress.update(storing_progress, advance=1)
                self.console.print("[green]Your Private Stored Successfully[/green]")

    def logged_in_shell(self)->None:
        action_map = {
            "Send a message": self.send_message_shell,
            "Inbox": self.inbox_shell,
            "Change password": self.change_password_shell,
            "Turn on the safe": self.turn_on_safe,
            "Logout": self.logout
        }
        action = self.prompt_user_for_an_action(list(action_map.keys()))
        action_map[action]()

    def send_message_shell(self):
        message = questionary.form(
            receivers=questionary.checkbox(
               "Choose your receivers:",
                choices=[{"name": user["username"], "value": user} for user in self.users]
            ),
            text=questionary.text("Enter you message's text:", multiline=True),
        )
        
        messages = list(map(lambda receiver:  self.create_message_object(message['text'], self.user['username'], receiver['username'], self.cached_private_key, receiver['public_key']), message['receivers']))
        self.send_messages(messages, len(self.users))

    def inbox_shell(self):
        pass

    def change_password_shell(self):
        pass
    
    def turn_on_safe(self):
        pass

    def logout(self)->None:
        self.user = None

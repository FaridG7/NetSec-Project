import questionary
import time
import os
from rich.console import Console
from rich.progress import Progress

from modules.Safe import Safe
from modules.User import User
from modules.Loader import Loader
from modules.Message import Message, MessageBody
from modules.HelperUtilities import HelperUtilities
from modules.exceptions import BadInput, ConflictError, LoginFailed, PasswordHashFileNotFound, PrivateKeyFileNotFound

class MailBox(Loader):
    console: Console
    cached_user_private_key_pem: bytes | None
    inbox: list[MessageBody]

    def __init__(self):
        super().__init__()
        self.console = Console()
        self.cached_user_private_key_pem = None
        self.inbox = []

    def run(self)->None:
        while True:
            if self.user:
                self.logged_in_shell()
            else:
                self.anonymous_shell()

    def prompt_user(self, message:str, choices: list[str])->str:
        self.console.clear()
        self.console.print("[bold cyan]MailBox(My Network Security Class Project)")
        return questionary.select(

            f"{message}",
            choices=choices
        ).ask()
    
    def prompt_user_for_an_action(self, actions:list[str])->str:
        return self.prompt_user("Choose an Action", actions)

    def anonymous_shell(self)->None:
        action_map = {
            "Register a new User(as Admin)": self.register_user_shell,
            "Login": self.login_shell,
            "Help": self.help_shell,
            "Exit": self.exit,
        }
        action = self.prompt_user_for_an_action(list(action_map.keys()))
        action_map[action]()

    def register_user_shell(self):
        try:
            path = questionary.path(
                "Please enter the path to the Root Certificate private key file:",
                default=".", 
                validate=lambda path: True if os.path.isfile(path) else "File does not exist. Please enter a valid file path.",
            ).ask()

            if path:
                registrar_private_key_pem = HelperUtilities.restore_private_key_from_backup_file(path)
            else:
                self.console.print(f"[bold yellow]Could not find the Root Certificate private key[/bold yellow]")
                exit()
        except KeyboardInterrupt:
            self.console.print(f"[bold yellow]Could not find the Root Certificate private key[/bold yellow]")
            exit()

        while True:
            username = self.console.input("[bold yellow]Enter Username[/bold yellow][bold orange](enter 0 to abort):[/bold orange] ")
            if username == '0':
                return
            elif not User.is_duplicate_user_name(self.users, username):
                break
            self.console.print(f"[bold yellow]'{username}' already exists[/bold yellow]")
        while True:
            password = self.console.input("[bold yellow]Enter Password(between 8 to 16 characters with standard format)[/bold yellow][bold orange](enter 0 to abort):[/bold orange] ")
            if password == '0':
                return
            elif HelperUtilities.is_valid_password_format(password):
                break
            self.console.print(f"[bold yellow]Please enter a standard password[/bold yellow]")

        try:
            with Progress() as progress:
                register_progress = progress.add_task("[cyan]Register process started...", total=100)
                for i in range(20):
                    time.sleep(0.02)
                    progress.update(register_progress, advance=1)

                self.users, private_key_pem = User.register_user(self.users, username, registrar_private_key_pem)
                
                for i in range(80):
                    time.sleep(0.02)
                    progress.update(register_progress, advance=1)
                progress.stop()

            self.console.print("[green]Register Successful[/green]")
            self.console.print("[bold yellow]Backup private key file generated[/bold yellow]")
            self.console.print("[yellow]Store it somewhere safe or your account will be useless without it![yellow]")

            _, salt_str = Safe.store_password_hash_locally(username, password)
            Safe.store_private_key_locally(username, password, salt_str, private_key_pem )

        except (ConflictError, BadInput) as e:
            self.console.print(f"[bold red]{e}[/bold red]")
    
    def help_shell(self):
        pass

    def exit(self):
        self.console.print("[cyan]Bye👋")
        exit(0)

    def login_shell(self)->None:
        print([u.username for u in self.users])
        while True:
            username = self.console.input("[bold yellow]Enter Username[/bold yellow][bold orange](type 'exit' to exit):[/bold orange] ")
            if username == 'exit':
                return
            with Progress() as progress:
                login_task = progress.add_task("[cyan]Loggining in...", total=100)
                try:
                    for i in range(40):
                        time.sleep(0.01)
                        progress.update(login_task, advance=1)
                    
                    self.user = User.login(self.users, username)
                    
                    for i in range(60):
                        time.sleep(0.01)
                        progress.update(login_task, advance=1)

                    progress.stop()
                    self.console.print("[green]Login Successful[/green]")
                    break
                except LoginFailed as e:
                    progress.stop()
                    self.console.print(f"[bold red]{e}[/bold red]")
                    self.console.input("[bold yellow]Press [Enter] to continue...[/bold yellow]")

        try:
            password_hash_digest, salt = Safe.restore_local_password_hash(self.user.username)
            while True:
                password = self.console.input("[bold yellow]Enter Password[/bold yellow][bold orange](enter 0 to abort):[/bold orange]  ")
                if password == '0':
                    self.user = None
                    return
                elif HelperUtilities.is_password_verified(password, password_hash_digest, salt):
                    break

                self.console.print("[bold red]Incorrect Password[/bold red]")
        except PasswordHashFileNotFound as e:
            self.console.print(f"[bold red]{e}[/bold red]")
            self.console.input("[bold yellow]Press [Enter] to continue...[/bold yellow]")
            return
        
        with Progress() as progress:
            private_key_restoring_task = progress.add_task("[cyan]Restoring private key...", total=100)
            try:
                for i in range(40):
                    time.sleep(0.01)
                    progress.update(private_key_restoring_task, advance=1)
                
                self.cached_user_private_key_pem = Safe.restore_local_private_key(self.user.username, password, salt)
                
                for i in range(60):
                    time.sleep(0.01)
                    progress.update(private_key_restoring_task, advance=1)
                
                progress.stop_task(private_key_restoring_task)
                self.console.print("[green]Locally Saved Private Key Found and Cached[/green]")
            except PrivateKeyFileNotFound as e:
                self.console.print(f"[bold red]{e}[/bold red]")
                self.private_key_recovery_shell(password, salt)
                if self.cached_user_private_key_pem is not None:
                    self.inbox = Message.load_inbox(self.user.username, password, salt, self.cached_user_private_key_pem, self.users)
                else:
                    raise Exception()

    def private_key_recovery_shell(self, password:str, salt:bytes):
        if self.user is None:
            raise Exception()

        self.console.print(f"[bold yellow]Starting Private Key Recovery Operation[/bold yellow]")
        
        try:
            path = questionary.path(
                "Please enter the path to the private key backup file:",
                default=".", 
                validate=lambda path: True if os.path.isfile(path) else "File does not exist. Please enter a valid file path.",
            ).ask()

            if path:
                self.cached_user_private_key_pem = HelperUtilities.restore_private_key_from_backup_file(path)
                Safe.store_private_key_locally(self.user.username, password, salt, self.cached_user_private_key_pem)
            else:
                self.console.print(f"[bold yellow]Private Key Recovery Operation Cancelled[/bold yellow]")
                self.exit()
        except KeyboardInterrupt:
            self.console.print(f"[bold yellow]Private Key Recovery Operation Cancelled[/bold yellow]")
            self.exit()

    def logged_in_shell(self)->None:
        action_map = {
            "Write a message": self.write_message_shell,
            "Inbox": self.inbox_shell,
            "Change password": self.change_password_shell,
            "Logout & Send message(s)": self.logout_and_send_messages,
            "Logout But Don't Send message(s)": self.logout(),
            "Help": self.help_shell,
        }
        action = self.prompt_user_for_an_action(list(action_map.keys()))
        action_map[action]()

    def write_message_shell(self):
        message = questionary.form(
            receivers=questionary.checkbox(
               "Choose your receivers:",
                choices=[{"name": user.username, "value": user} for user in self.users]
            ),
            text=questionary.text("Enter you message's text:", multiline=True),
        ).ask()
        for receiver in message["receivers"]:
            if receiver in self.cached_messages and self.cached_messages[receiver]:
                self.cached_messages[receiver] += f"\n{message['text']}"
            else:
                self.cached_messages[receiver] = message['text']

    def inbox_shell(self):
        if not self.inbox:
            self.console.print("[bold]Your Inbox is Empty[/bold]")
            self.console.input("[bold yellow]Press [Enter] to continue...[/bold yellow]")
            return
        while True:
            self.console.clear()
            self.console.print("[bold cyan]Inbox:")

            choices = [
                {
                    "name": f"ID: {getattr(msg, 'id', i+1)} | Time: {getattr(msg, 'timestamp', 'N/A')}",
                    "value": i
                }
                for i, msg in enumerate(self.inbox)
            ]
            choices.append({"name": "Back", "value": None})

            selected = questionary.select(
                "Select a message to view details:",
                choices=choices
            ).ask()

            if selected is not None:
                msg = self.inbox[selected]
                message_details = (
                    f"[bold yellow]From:[/bold yellow] {msg.sender_username}\n"
                    f"[bold yellow]To:[/bold yellow] {msg.receiver_username}\n"
                    f"[bold yellow]Time:[/bold yellow] {getattr(msg, 'timestamp', 'N/A')}\n"
                    f"[bold yellow]ID:[/bold yellow] {getattr(msg, 'id', selected+1)}\n"
                    f"\n[bold yellow]Text:[/bold yellow]\n{msg.text}"
                )
               
                with self.console.pager():
                    self.console.print(message_details)
            else:
                break

    def change_password_shell(self):
        if (self.user is None) or (self.cached_user_private_key_pem is None):
            raise Exception()
        
        with Progress() as progress:
            load_password_hash_task = progress.add_task("[cyan]Restoring Password Hash & Salt...", total=100)
            try:
                for i in range(40):
                    time.sleep(0.01)
                    progress.update(load_password_hash_task, advance=1)
                
                password_hash_digest, salt_str = Safe.restore_local_password_hash(self.user.username)
                
                for i in range(60):
                    time.sleep(0.01)
                    progress.update(load_password_hash_task, advance=1)

                progress.stop()
                self.console.print("[green]Restoring Password Hash & Salt Successful[/green]")

                while True:
                    password = self.console.input("[bold yellow]Enter Your Current Password[/bold yellow][bold orange](enter 0 to abort):[/bold orange]  ")
                    if password == '0':
                        return
                    elif HelperUtilities.is_password_verified(password, password_hash_digest, salt_str):
                        break

                    self.console.print("[bold red]Incorrect Password[/bold red]")

                while True:
                    new_password = self.console.input("[bold yellow]Enter The New Password(between 8 to 16 characters with standard format)[/bold yellow][bold orange](enter 0 to abort):[/bold orange]  ")
                    if new_password == '0':
                        return
                    elif HelperUtilities.is_valid_password_format(new_password):
                        break

                    self.console.print("[bold red]Incorrect Password[/bold red]")

                change_password_task = progress.add_task("[cyan]Restoring Password Hash & Salt...", total=200)

                self.console.print("[orange]Changing Password Process Started[/orange]")
                for i in range(40):
                    time.sleep(0.01)
                    progress.update(change_password_task, advance=1)

                Safe.change_password(self.user.username, password, new_password, self.cached_user_private_key_pem )

                for i in range(60):
                    time.sleep(0.01)
                    progress.update(change_password_task, advance=1)

                progress.stop()
                self.console.print("[green]Private Key Saved Locally with New Password[/green]")

            except PasswordHashFileNotFound as e:
                self.console.print(f"[bold red]{e}[/bold red]")
            finally:
                progress.stop()

    def logout(self):
        self.user = None
        self.cached_user_private_key_pem = None
        self.inbox = []
        self.cached_messages = {}

    def logout_and_send_messages(self)->None:
        if (self.user is None) or (self.cached_user_private_key_pem is None):
            raise Exception()
        with Progress() as progress:
            send_messages_tesk = progress.add_task("[cyan]Sending Messages...", total=100)
            for i in range(10):
                time.sleep(0.01)
                progress.update(send_messages_tesk, advance=1)
                
            messages = [Message(text, self.cached_user_private_key_pem, self.user.username, receiver.username, receiver.public_key_pem) for receiver, text in self.cached_messages.items()]
            Message.send_messages(messages, len(self.users))

            send_messages_tesk = progress.add_task("[cyan]Sending Messages...", total=100)
            for i in range(85):
                time.sleep(0.01)
                progress.update(send_messages_tesk, advance=1)
            
            self.logout()

            for i in range(5):
                time.sleep(0.01)
                progress.update(send_messages_tesk, advance=1)
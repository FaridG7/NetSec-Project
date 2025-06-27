import questionary
import time
import os
from rich.console import Console
from rich.progress import Progress
from rich.prompt import Prompt

from modules.Safe import Safe
from modules.User import User
from modules.Message import Message, MessageBody
from modules.Loader import Loader
from modules.HelperUtilities import HelperUtilities
from modules.exceptions import LoginFailed, PasswordHashFileNotFound, PrivateKeyFileNotFound

class MailBox(Loader):
    console: Console
    cached_private_key_pem: bytes
    inbox: list[MessageBody]

    def __init__(self):
        self.console = Console()

    def run(self)->None:
        self.console.clear()
        self.console.print("[bold cyan]MailBox(My Network Security Class Project)")
        while True:
            if self.user:
                self.logged_in_shell()
            else:
                self.anonymous_shell()
    
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

    def anonymous_shell(self)->None:
        action_map = {
            "Login": self.login_shell,
            "Help": self.help_shell,
            "Help": self.exit,
        }
        action = self.prompt_user_for_an_action(list(action_map.keys()))
        action_map[action]()

    def help_shell(self):
        pass

    def exit(self):
        self.console.print("[cyan]Bye👋")
        exit(0)

    def login_shell(self)->None:
        with Progress() as progress:
            username = self.console.input("[bold yellow]Enter Username[/bold yellow][bold orange](type 'exit' to exit):[/bold orange] ")
            if username == 'exit':
                return
            login_task = progress.add_task("[cyan]Loggining in...", total=200)
            try:
                for i in range(40):
                    time.sleep(0.01)
                    progress.update(login_task, advance=1)
                
                self.user = User.login(self.users, username)
                password_hash_digest, salt_str = Safe.restore_local_password_hash(self.user['username'])
                
                for i in range(60):
                    time.sleep(0.01)
                    progress.update(login_task, advance=1)

                self.console.print("[green]Login Successful[/green]")

                while True:
                    password = self.console.input("[bold yellow]Enter Password[/bold yellow][bold orange](enter 0 to abort):[/bold orange]  ")
                    if password == '0':
                        return
                    elif HelperUtilities.is_password_verified(password, password_hash_digest, salt_str):
                        break

                    self.console.print("[bold red]Incorrect Password[/bold red]")

                self.console.print("[ornage]Restoring Private Key[/ornage]")
                for i in range(40):
                    time.sleep(0.01)
                    progress.update(login_task, advance=1)

                self.cached_private_key_pem = Safe.restore_local_private_key(self.user["username"], password, salt_str)

                for i in range(60):
                    time.sleep(0.01)
                    progress.update(login_task, advance=1)

                self.console.print("[green]Locally Saved Private Key Found and Cached[/green]")
            
            except PasswordHashFileNotFound as e:
                self.console.print(f"[bold red]{e.message}[/bold red]")
            except LoginFailed as e:
                self.console.print(f"[bold red]{e.message}[/bold red]")
            except PrivateKeyFileNotFound as e:
                self.console.print(f"[bold red]{e.message}[/bold red]")
            finally:
                progress.stop()
                if not self.cached_private_key_pem:
                    self.private_key_recovery_shell(password, salt_str)
                # Message.load_inbox()
                

    def private_key_recovery_shell(self, password:str, salt_str:str):
        self.console.print(f"[bold yellow]Starting Private Key Recovery Operation[/bold yellow]")
        
        try:
            path = questionary.path(
                "Please enter the path to the private key backup file:",
                default=".", 
                validate=lambda path: True if os.path.isfile(path) else "File does not exist. Please enter a valid file path.",
            ).ask()

            if path:
                self.cached_private_key_pem = HelperUtilities.restore_private_key_from_backup_file(path)
                Safe.store_private_key_locally(self.user['username'], password, salt_str, self.cached_private_key_pem)
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
            "Send message(s) & Logout": self.send_messsages_and_logout,
            "Help": self.help_shell,
        }
        action = self.prompt_user_for_an_action(list(action_map.keys()))
        action_map[action]()

    def write_message_shell(self):
        message = questionary.form(
            receivers=questionary.checkbox(
               "Choose your receivers:",
                choices=[{"name": user["username"], "value": user} for user in self.users]
            ),
            text=questionary.text("Enter you message's text:", multiline=True),
        )
        for receiver in message["receivers"]:
            if receiver in self.cached_messages and self.cached_messages[receiver]:
                self.cached_messages[receiver] += message['text']
            else:
                self.cached_messages[receiver] = message['text']

    def inbox_shell(self):
        pass

    def change_password_shell(self):
        with Progress() as progress:
            change_password_task = progress.add_task("[cyan]Restoring Password Hash & Salt...", total=200)
            try:
                for i in range(40):
                    time.sleep(0.01)
                    progress.update(change_password_task, advance=1)
                
                password_hash_digest, salt_str = Safe.restore_local_password_hash(self.user['username'])
                
                for i in range(60):
                    time.sleep(0.01)
                    progress.update(change_password_task, advance=1)

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

                self.console.print("[ornage]Changing Password Process Started[/ornage]")
                for i in range(40):
                    time.sleep(0.01)
                    progress.update(change_password_task, advance=1)

                HelperUtilities.change_password(self.user.username, password, new_password, self.cached_private_key_pem )

                for i in range(60):
                    time.sleep(0.01)
                    progress.update(change_password_task, advance=1)

                self.console.print("[green]Private Key Saved Locally with New Password[/green]")

            except PasswordHashFileNotFound as e:
                self.console.print(f"[bold red]{e.message}[/bold red]")
            finally:
                progress.stop()

    
    def send_messsages_and_logout(self)->None:
        with Progress() as progress:
            send_messages_tesk = progress.add_task("[cyan]Sending Messages...", total=100)
            for i in range(10):
                time.sleep(0.01)
                progress.update(send_messages_tesk, advance=1)
                
            messages = [Message(text, self.cached_private_key_pem, self.user.username, receiver['username'], receiver['public_key_pem']) for receiver, text in self.cached_messages.items()]
            Message.send_messages(messages, len(self.users))

            for i in range(85):
                time.sleep(0.01)
                progress.update(send_messages_tesk, advance=1)
            
            self.user = None

            for i in range(5):
                time.sleep(0.01)
                progress.update(send_messages_tesk, advance=1)

from modules.register import register_user
from modules.load_users import load_users
from modules.create_new_room import create_new_room

user_actions = {
    "register": {"module":register_user,"title":"register a new user"},
    "create_new_room": {"module":create_new_room,"title":"create a new chat room"},
}

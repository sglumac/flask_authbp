from typing import Callable, NamedTuple, Optional


Username = str
PasswordHash = str


class Authentication(NamedTuple):
    find_password_hash: Callable[[Username], Optional[PasswordHash]]
    store_user: Callable[[Username, PasswordHash], None]
    generate_session_info: Callable[[Username], None]

from enum import IntEnum


class ActionToken(IntEnum):
    PAD = 0
    UNK = 1

    LOGIN_SUCCESS = 2
    LOGIN_FAILURE = 3
    LOGOFF = 4

    FILE_ACCESS = 5
    SENSITIVE_FILE_ACCESS = 6
    MASS_FILE_ACCESS = 7

    USB_CONNECT = 8
    USB_ACTIVITY = 9
    USB_COPY = 10

    PROCESS_EXECUTION = 11
    POWERSHELL = 12
    SCRIPT_EXECUTION = 13
    ARCHIVE_CREATE = 14

    EMAIL_SEND = 15
    WEB_UPLOAD = 16
    EXTERNAL_TRANSFER = 17

    NETWORK_ACCESS = 18
    OTHER = 19

    PRIVILEGED_LOGON = 20
    EXPLICIT_CREDENTIAL_LOGON = 21
    WORKSTATION_LOCK = 22
    WORKSTATION_UNLOCK = 23
    AUTH_TICKET = 24


TOKEN_NAMES = {int(token): token.name for token in ActionToken}
NAME_TO_ID = {token.name: int(token) for token in ActionToken}

RISKY_ACTIONS = {
    "LOGIN_FAILURE",
    "SENSITIVE_FILE_ACCESS",
    "MASS_FILE_ACCESS",
    "USB_CONNECT",
    "USB_ACTIVITY",
    "USB_COPY",
    "POWERSHELL",
    "SCRIPT_EXECUTION",
    "ARCHIVE_CREATE",
    "EMAIL_SEND",
    "WEB_UPLOAD",
    "EXTERNAL_TRANSFER",
    "PRIVILEGED_LOGON",
    "EXPLICIT_CREDENTIAL_LOGON",
}


def token_id(name: str) -> int:
    return NAME_TO_ID.get(str(name).strip().upper(), int(ActionToken.UNK))


def token_name(idx: int) -> str:
    return TOKEN_NAMES.get(int(idx), "UNK")

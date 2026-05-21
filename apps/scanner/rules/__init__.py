from .base import FTPAnonymousRule, SMBv1Rule

ALL_RULES = [
    FTPAnonymousRule(),
    SMBv1Rule(),
]
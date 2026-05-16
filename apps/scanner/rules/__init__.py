from .base import FTPAnonymousRule, SMBv1Rule, RedisNoAuthRule

ALL_RULES = [
    FTPAnonymousRule(),
    SMBv1Rule(),
    RedisNoAuthRule(),
]

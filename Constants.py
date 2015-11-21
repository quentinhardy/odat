# -*- coding: utf-8 -*
import string

DESCRIPTION = ""\
"""
            _  __   _  ___ 
           / \|  \ / \|_ _|
          ( o ) o ) o || | 
           \_/|__/|_n_||_| 
-------------------------------------------
  _        __           _           ___ 
 / \      |  \         / \         |_ _|
( o )       o )         o |         | | 
 \_/racle |__/atabase |_n_|ttacking |_|ool 
-------------------------------------------

By Quentin Hardy (quentin.hardy@bt.com or qhardyfr@gmail.com)
"""
CURRENT_VERSION = "Version 1.6 - 2015/07/14"
DEFAULT_SID_MIN_SIZE = 1
DEFAULT_SID_MAX_SIZE = 2
MAX_HELP_POSITION=60
DEFAULT_SID_FILE = "sids.txt"
DEFAULT_ACCOUNT_FILE = "accounts/accounts.txt"
DEFAULT_TIME_SLEEP = 0
DEFAULT_SID_CHARSET = string.ascii_uppercase
EXIT_NO_SIDS = 100
EXIT_NO_ACCOUNTS = 101
EXIT_BAD_CONNECTION = 102
EXIT_BAD_CMD_PARAMETER = 103
EXIT_MISS_ARGUMENT = 104
EXIT_MISS_MODULE = 105
ALL_IS_OK=0
TIMEOUT_VALUE = 5
PASSWORD_EXTENSION_FILE = ".odat.save"
CHALLENGE_EXT_FILE = ".odat.challenge"
SHOW_SQL_REQUESTS_IN_VERBOSE_MODE = False
MAX_WIDTH_TEXTTABLES = 120
DEFAULT_ENCODING = 'utf8'
#SEARCH module
PATTERNS_COLUMNS_WITH_PWDS = [
	'%mdp%',
	'%pwd%',
	'%pass%',
	"%contraseña%",
	"%clave%",
	"%chiave%",
	"%пароль%",
	"%wachtwoord%",
	"%hasło%",
	"%senha%",
	]

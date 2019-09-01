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

By Quentin Hardy (quentin.hardy@protonmail.com or quentin.hardy@bt.com)
"""
CURRENT_VERSION = "Version 3.O - 2019/09/01"
DEFAULT_SID_MIN_SIZE = 1
DEFAULT_SID_MAX_SIZE = 2
MAX_HELP_POSITION=22
MAX_SUB_HELP_POSITION=45
MAX_SPECIAL_SUB_HELP_POSITION = 60
MAX_HELP_WIDTH = 150
DEFAULT_SID_FILE = "sids.txt"
DEFAULT_ACCOUNT_FILE = "accounts/accounts.txt"
DEFAULT_LOGINS_FILE = "accounts/logins.txt"
DEFAULT_PWDS_FILE = "accounts/pwds.txt"
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
MAX_WIDTH_TEXTTABLES = 120
DEFAULT_ENCODING = 'utf8'
TIMEOUT_TNS_CMD = 30
DEFAULT_LOCAL_LISTENING_PORT_TNS_POISON = 1522
DEFAULT_SLEEPING_TIME_TNS_POISON = 10
MAX_TIMEOUT_VALUE_TNS_POISON = 10
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
EXPLOITABLE_SYSTEM_PRIVILEGES = [
	'CREATE ANY PROCEDURE',
	'ANALYZE ANY',
	'CREATE ANY TRIGGER',
	'CREATE ANY INDEX',
]

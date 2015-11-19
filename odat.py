#!/usr/bin/python
# -*- coding: utf-8 -*-

#PYTHON_ARGCOMPLETE_OK
try:
	import argcomplete
	ARGCOMPLETE_AVAILABLE = True
except ImportError:
	ARGCOMPLETE_AVAILABLE = False
#PYTHON_COLORLOG_OK
try:
	from colorlog import ColoredFormatter
	COLORLOG_AVAILABLE = True
except ImportError:
	COLORLOG_AVAILABLE = False

import argparse, logging, platform, cx_Oracle, string, os, sys
from Utils import areEquals, configureLogging,ErrorSQLRequest, sidHasBeenGiven, anAccountIsGiven, ipOrNameServerHasBeenGiven
from sys import exit,stdout

from Constants import *
from Output import Output
from Tnscmd import runTnsCmdModule, runCheckTNSPoisoning
from UtlFile import UtlFile, runUtlFileModule
from DbmsAdvisor import DbmsAdvisor,runDbmsadvisorModule
from DbmsScheduler import DbmsScheduler,runDbmsSchedulerModule
from UtlHttp import UtlHttp,runUtlHttpModule
from HttpUriType import HttpUriType,runHttpUriTypeModule
from Java import Java,runjavaModule
from Info import Info
from PasswordGuesser import PasswordGuesser, runPasswordGuesserModule
from SIDGuesser import SIDGuesser, runSIDGuesserModule
from SMB import SMB, runSMBModule
from Ctxsys import Ctxsys,runCtxsysModule
from Passwords import Passwords,runPasswordsModule
from DbmsXslprocessor import DbmsXslprocessor,runDbmsXslprocessorModule
from ExternalTable import ExternalTable,runExternalTableModule
from UtlTcp import UtlTcp,runUtlTcpModule
from DbmsLob import DbmsLob,runDbmsLob
from CVE_2012_3137 import CVE_2012_3137,runCVE20123137Module
from Oradbg import Oradbg,runOradbgModule
from UsernameLikePassword import UsernameLikePassword,runUsernameLikePassword
from Search import runSearchModule
from Unwrapper import runUnwrapperModule

def runClean (args):
	'''
	Clean traces and logs
	'''
	nbFileDeleted, nbFileToDelete = 0, 0
	exts=(PASSWORD_EXTENSION_FILE,CHALLENGE_EXT_FILE)
	pathOfOdat = os.path.dirname(os.path.abspath(__file__))
	for root, dirs, files in os.walk(pathOfOdat):
		for currentFile in files:
			logging.debug("Processing file: {0}".format(currentFile))
			if any(currentFile.lower().endswith(ext) for ext in exts):
				rep = raw_input("Do you want to delete this file (Y for yes): {0}/{1}? ".format(root, currentFile))
				if rep.replace('\n','') == 'Y' : 
					os.remove(os.path.join(root, currentFile))
					logging.info("Removing {0}/{1}".format(root, currentFile))
					nbFileDeleted += 1
				nbFileToDelete += 1
	args['print'].goodNews("Finish: {0}/{1} file(s) deleted".format(nbFileDeleted, nbFileToDelete))

def runAllModules(args):
	'''
	Run all modules
	'''
	connectionInformation, validSIDsList = {}, []
	#0)TNS Poinsoning
	if args['no-tns-poisoning-check'] == False:
		runCheckTNSPoisoning(args)
	else:
		logging.info("Don't check if the target is vulnerable to TNS poisoning because the option --no-tns-poisoning-check is enabled in command line")
	#A)SID MANAGEMENT
	if args['sid'] == None :
		logging.debug("Searching valid SIDs")
		validSIDsList = runSIDGuesserModule(args)
		args['user'], args['password'] = None, None 
	else :
		validSIDsList = [args['sid']]
	#B)ACCOUNT MANAGEMENT
	if args['credentialsFile'] == True :
		logging.debug("Loading credentials stored in the {0} file".format(args['accounts-file']))
		#Load accounts from file
		passwordGuesser = PasswordGuesser(args, args['accounts-file'])
		validAccountsList = passwordGuesser.getAccountsFromFile()
		for aSid in validSIDsList:
			for anAccount in validAccountsList:
				if connectionInformation.has_key(aSid) == False: connectionInformation[aSid] = [[anAccount[0], anAccount[1]]]
				else : connectionInformation[aSid].append([anAccount[0], anAccount[1]])
	elif args['user'] == None and args['password'] == None:
		for sid in validSIDsList:
			args['print'].title("Searching valid accounts on the {0} SID".format(sid))
			args['sid'] = sid
			passwordGuesser = PasswordGuesser(args,args['accounts-file'])
			passwordGuesser.searchValideAccounts()
			validAccountsList = passwordGuesser.valideAccounts
			if validAccountsList == {}:
				args['print'].badNews("No found a valid account on {0}:{1}/{2}".format(args['server'], args['port'], args['sid']))
				exit(EXIT_NO_ACCOUNTS)
			else :
				args['print'].goodNews("Accounts found on {0}:{1}/{2}: {3}".format(args['server'], args['port'], args['sid'],validAccountsList))
				for aLogin, aPassword in validAccountsList.items(): 
					if connectionInformation.has_key(sid) == False: connectionInformation[sid] = [[aLogin,aPassword]]
					else : connectionInformation[sid].append([aLogin,aPassword])
	else:
		validAccountsList = {args['user']:args['password']}
		for aSid in validSIDsList:
			for aLogin, aPassword in validAccountsList.items():
				if connectionInformation.has_key(aSid) == False: connectionInformation[aSid] = [[aLogin,aPassword]]
				else : connectionInformation[aSid].append([aLogin,aPassword])
	#C)ALL OTHERS MODULES
	if sidHasBeenGiven(args) == False : return EXIT_MISS_ARGUMENT
	#elif anAccountIsGiven(args) == False : return EXIT_MISS_ARGUMENT
	for aSid in connectionInformation.keys():
		for loginAndPass in connectionInformation[aSid]:
			args['sid'] , args['user'], args['password'] = aSid, loginAndPass[0],loginAndPass[1]
			args['print'].title("Testing all modules on the {0} SID with the {1}/{2} account".format(args['sid'],args['user'],args['password']))
			#INFO ABOUT REMOTE SERVER
			info = Info(args)
			status = info.connection()
			if isinstance(status,Exception):
				args['print'].badNews("Impossible to connect to the remote database: {0}".format(str(status).replace('\n','')))
				break
			info.loadInformationRemoteDatabase()
			args['info'] = info
			#UTL_HTTP
			utlHttp = UtlHttp(args)
			status = utlHttp.connection()
			utlHttp.testAll()
			#HTTPURITYPE
			httpUriType = HttpUriType(args)
			httpUriType.testAll()
			#UTL_FILE
			utlFile = UtlFile(args)
			utlFile.testAll()
			#JAVA
			java = Java(args)
			java.testAll()
			#DBMS ADVISOR
			dbmsAdvisor = DbmsAdvisor(args)
			dbmsAdvisor.testAll()
			#DBMS Scheduler
			dbmsScheduler = DbmsScheduler(args)
			dbmsScheduler.testAll()
			#CTXSYS
			ctxsys = Ctxsys(args)
			ctxsys.testAll()
			#Passwords
			passwords = Passwords(args)
			passwords.testAll()
			#DbmsXmldom
			dbmsXslprocessor = DbmsXslprocessor(args)
			dbmsXslprocessor.testAll()
			#External Table
			externalTable = ExternalTable(args)
			externalTable.testAll()
			#Oradbg
			oradbg = Oradbg(args)
			oradbg.testAll()
			#DbmsLob
			dbmsLob = DbmsLob(args)
			dbmsLob.testAll()
			#SMB
			smb = SMB(args)
			smb.testAll()
			smb.close() #Close the socket to the remote database
			#CVE_2012_3137
			cve = CVE_2012_3137 (args)
			cve.testAll()
	#usernamelikepassword
	args['run'] = True
	runUsernameLikePassword(args)

def configureLogging(args):
	'''
	Configure le logging
	'''	
	logformatNoColor = "%(asctime)s %(levelname)-3s -: %(message)s"
	logformatColor   = "%(bg_black)s%(asctime)s%(reset)s %(log_color)s%(levelname)-3s%(reset)s %(bold_black)s-:%(reset)s %(log_color)s%(message)s%(reset)s"#%(bold_black)s%(name)s:%(reset)s
	datefmt = "%H:%M:%S"
	#Set log level
	if args['verbose']==0: level=logging.WARNING
	elif args['verbose']==1: level=logging.INFO
	elif args['verbose']>=2: level=logging.DEBUG
	#Define color for logs
	if args['no-color'] == False and COLORLOG_AVAILABLE==True:
		formatter = ColoredFormatter(logformatColor, datefmt=datefmt,log_colors={'CRITICAL': 'bold_red', 'ERROR': 'red', 'WARNING': 'yellow'})
	else : 
		formatter = logging.Formatter(logformatNoColor, datefmt=datefmt)
	stream = logging.StreamHandler()
	#stream.setLevel(level)
	stream.setFormatter(formatter)
	root = logging.getLogger()
	root.setLevel(level)
	root.addHandler(stream)

def main():
	#Parse Args
	parser = argparse.ArgumentParser(description=DESCRIPTION, formatter_class=argparse.RawTextHelpFormatter)
	#1- Parent parsers
	parser.add_argument('--version', action='version', version=CURRENT_VERSION)
	#1.0- Parent parser: optional
	PPoptional = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPoptional._optionals.title = "optional arguments"
	PPoptional.add_argument('-v', dest='verbose', action='count', default=0, help='enable verbosity (-vv for more)')
	PPoptional.add_argument('--sleep', dest='timeSleep', required=False, type=float, default=DEFAULT_TIME_SLEEP, help='time sleep between each test or request (default: %(default)s)')
	PPoptional.add_argument('--encoding', dest='encoding', required=False, default=DEFAULT_ENCODING, help='output encoding (default: %(default)s)')
	#1.1- Parent parser: connection options
	PPconnection = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPconnection._optionals.title = "connection options"
	PPconnection.add_argument('-s', dest='server', required=False, help='server')
	PPconnection.add_argument('-p', dest='port', default=1521, required=False, help='port (Default 1521)')
	PPconnection.add_argument('-U', dest='user', required=False, help='Oracle username')
	PPconnection.add_argument('-P', dest='password', required=False, default=None, help='Oracle password')
	PPconnection.add_argument('-d', dest='sid', required=False, help='Oracle System ID (SID)')
	PPconnection.add_argument('--sysdba', dest='SYSDBA', action='store_true', default=False, help='connection as SYSDBA')
	PPconnection.add_argument('--sysoper', dest='SYSOPER', action='store_true', default=False, help='connection as SYSOPER')
	#1.2- Parent parser: output options
	PPoutput = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPoutput._optionals.title = "output configurations"
	PPoutput.add_argument('--no-color', dest='no-color', required=False, action='store_true', help='no color for output')
	PPoutput.add_argument('--output-file',dest='outputFile',default=None,required=False,help='save results in this file')
	#1.3- Parent parser: all option
	PPallModule = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPallModule._optionals.title = "all module options"
	PPallModule.add_argument('-C', dest='credentialsFile', action='store_true', required=False, default=False, help='use credentials stored in the --accounts-file file (disable -P and -U)')
	PPallModule.add_argument('--no-tns-poisoning-check', dest='no-tns-poisoning-check', action='store_true', required=False, default=False, help="don't check if target is vulnreable to TNS poisoning")
	#1.3- Parent parser: TNS cmd
	PPTnsCmd = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPTnsCmd._optionals.title = "TNS cmd options"
	PPTnsCmd.add_argument('--ping', dest='ping', action='store_true', required=False, default=False, help='send a TNS ping command to get alias')
	PPTnsCmd.add_argument('--version', dest='version', action='store_true', required=False, default=False, help='send a TNS version command to try to get verion')
	PPTnsCmd.add_argument('--status', dest='status', action='store_true', required=False, default=False, help='send a TNS status command to get the status')
	PPTnsCmd.add_argument('--tns-poisoning', dest='checkTNSPoisoning', action='store_true', required=False, default=False, help='check if target is vulnerable to TNS Poisoning (CVE-2012-1675)')
	#1.3- Parent parser: SID Guesser
	PPsidguesser = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPsidguesser._optionals.title = "SID guesser options"
	PPsidguesser.add_argument('--sids-min-size',dest='sids-min-size',required=False, type=int, default=DEFAULT_SID_MIN_SIZE, help='minimum size of SIDs for the bruteforce (default: %(default)s)')
	PPsidguesser.add_argument('--sids-max-size',dest='sids-max-size',required=False, type=int, default=DEFAULT_SID_MAX_SIZE, help='maximum size of SIDs for the bruteforce (default: %(default)s)')
	PPsidguesser.add_argument('--sid-charset',dest='sid-charset',required=False, default=DEFAULT_SID_CHARSET, help='charset for the sid bruteforce (default: %(default)s)')
	PPsidguesser.add_argument('--sids-file',dest='sids-file',required=False,metavar="FILE",default=DEFAULT_SID_FILE, help='file containing SIDs (default: %(default)s)')
	PPsidguesser.add_argument('--no-alias-like-sid',dest='no-alias-like-sid',action='store_true',required=False, help='no try listener ALIAS like SIDs (default: %(default)s)')	
	#1.4- Parent parser: Password Guesser
	PPpassguesser = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPpassguesser._optionals.title = "password guesser options"
	PPpassguesser.add_argument('--accounts-file',dest='accounts-file',required=False,metavar="FILE",default=DEFAULT_ACCOUNT_FILE,help='file containing Oracle credentials (default: %(default)s)')
	PPpassguesser.add_argument('--force-retry',dest='force-retry',action='store_true',help='allow to test multiple passwords for a user without ask you')
	#1.5- Parent parser: URL_HTTP
	PPutlhttp = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPutlhttp._optionals.title = "http commands"
	PPutlhttp.add_argument('--send',dest='send',default=None,required=False,nargs=3,metavar=('ip','port','namefile'),help='send the GET or POST request stored in namefile to ip:port')
	PPutlhttp.add_argument('--scan-ports',dest='scan-ports',default=None,required=False,nargs=2,metavar=('ip','ports'),help='scan tcp ports of a remote engine')
	PPutlhttp.add_argument('--save-reponse',dest='save-reponse',default=None,required=False,metavar='FILE',help='store the response server in this file')
	PPutlhttp.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.5- Parent parser: HTTPURITYPE
	PPhttpuritype = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPhttpuritype._optionals.title = "http commands"
	PPhttpuritype.add_argument('--url',dest='httpUrl',default=None,required=False,help='send a http GET request')
	PPhttpuritype.add_argument('--scan-ports',dest='scan-ports',default=None,required=False,nargs=2,metavar=('ip','ports'),help='scan tcp ports of a remote engine')
	PPhttpuritype.add_argument('--save-reponse',dest='save-reponse',default=None,required=False,metavar='FILE',help='store the response server in this file')
	PPhttpuritype.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.6- Parent parser: DBSMAdvisor 
	PPdbmsadvisor = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPdbmsadvisor._optionals.title = "DBMSAdvisor commands"
	PPdbmsadvisor.add_argument('--putFile',dest='putFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteNamefile','localFile'),help='put a file on the remote database server')
	PPdbmsadvisor.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')	
	#1.7- Parent parser: DBSMScheduler 
	PPdbmsscheduler = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPdbmsscheduler._optionals.title = "DBMSScheduler commands"
	PPdbmsscheduler.add_argument('--exec',dest='exec',default=None,required=False,help='execute a system command on the remote system')
	PPdbmsscheduler.add_argument('--reverse-shell',dest='reverse-shell',required=False,nargs=2,metavar=('ip','port'),help='get a reverse shell')
	PPdbmsscheduler.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')	
	#1.8- Parent parser: Java 
	PPjava = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPjava._optionals.title = "java commands"
	PPjava.add_argument('--exec',dest='exec',default=None,required=False,help='execute a system command on the remote system')
	PPjava.add_argument('--shell',dest='shell',action='store_true',required=False,help='get a shell on the remote system')
	PPjava.add_argument('--reverse-shell',dest='reverse-shell',required=False,nargs=2,metavar=('ip','port'),help='get a reverse shell')
	PPjava.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')	
	#1.9- Parent parser: Ctxsys 
	PPctxsys = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPctxsys._optionals.title = "ctxsys commands"
	PPctxsys.add_argument('--getFile',dest='getFile',default=None,required=False,help='read a file on the remote server')
	PPctxsys.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.10- Parent parser: Passwords 
	PPpasswords = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPpasswords._optionals.title = "passwords commands"
	PPpasswords.add_argument('--get-passwords',dest='get-passwords',action='store_true',required=False,help='get Oracle hashed passwords')
	PPpasswords.add_argument('--get-passwords-from-history',dest='get-passwords-from-history',action='store_true',required=False,help='get Oracle hashed passwords from history')
	PPpasswords.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.11- Parent parser: dbmsxslprocessor
	PPdbmsxslprocessor = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPdbmsxslprocessor._optionals.title = "DBMSXslprocessor commands"
	PPdbmsxslprocessor.add_argument('--putFile',dest='putFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteNamefile','localFile'),help='put a file on the remote database server')
	PPdbmsxslprocessor.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.12- Parent parser: externalTable
	PPexternaltable = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPexternaltable._optionals.title = "ExternalTable commands"
	PPexternaltable.add_argument('--exec',dest='exec',default=None,required=False,nargs=2,metavar=('remotePath','file'),help='execute a system command on the remote system (options no allowed)')
	PPexternaltable.add_argument('--getFile',dest='getFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteNamefile','localFile'),help='get a file from the remote database server')
	PPexternaltable.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.13- Parent parser: utlfile
	PPutlfile = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPutlfile._optionals.title = "utlfile commands"
	PPutlfile.add_argument('--getFile',dest='getFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteNamefile','localFile'),help='get a file from the remote database server')
	PPutlfile.add_argument('--putFile',dest='putFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteNamefile','localFile'),help='put a file to the remote database server')		
	PPutlfile.add_argument('--removeFile',dest='removeFile',default=None,required=False,nargs=2,metavar=('remotePath','remoteNamefile'),help='remove a file on the remote database server')	
	PPutlfile.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.14- Parent parser: UTL_TCP
	PPutltcp = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPutltcp._optionals.title = "utltcp commands"
	PPutltcp.add_argument('--send-packet',dest='send-packet',default=None,required=False,nargs=3,metavar=('ip','port','filename'),help='send a packet')
	PPutltcp.add_argument('--scan-ports',dest='scan-ports',default=None,required=False,nargs=2,metavar=('ip','ports'),help='scan tcp ports of a remote engine')	
	PPutltcp.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.15- Parent parser: STEAL_REMOTE_PASSWORDS
	PPstealRemotePass = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPstealRemotePass._optionals.title = "stealRemotePasswords commands"
	PPstealRemotePass.add_argument('-s', dest='server', required=True, help='server')
	PPstealRemotePass.add_argument('-p', dest='port', default=1521, required=False, help='port (Default 1521)')
	PPstealRemotePass.add_argument('-d', dest='sid', required=False, help='Oracle System ID (SID)')
	PPstealRemotePass.add_argument('-U', dest='user', required=False, help='Valid Oracle username')
	PPstealRemotePass.add_argument('-P', dest='password', required=False, default=None, help='Valid Oracle password')
	PPstealRemotePass.add_argument('--get-all-passwords',dest='get-all-passwords',action='store_true',default=None,required=False,help='get all hashed passwords thanks to the user/password list')
	PPstealRemotePass.add_argument('--decrypt-sessions',dest='decrypt-sessions',nargs=2,metavar=('sessionList.txt','passwordList.txt'),default=None,required=False,help='decrypt sessions stored in a file')	
	PPstealRemotePass.add_argument('--user-list',dest='user-list',required=False,metavar="FILE",default=DEFAULT_ACCOUNT_FILE,help='file containing Oracle credentials (default: %(default)s)')	
	PPstealRemotePass.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.16- Parent parser: Oradbg
	PPoradbg = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPoradbg._optionals.title = "oradbg commands"
	PPoradbg.add_argument('--exec',dest='exec',default=None,required=False,help='execute a system command on the remote system (no args allowed)')
	PPoradbg.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.12- Parent parser: DBMS_LOB
	PPdbmsLob = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPdbmsLob._optionals.title = "DBMS_LOB commands (new)"
	PPdbmsLob.add_argument('--getFile',dest='getFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteNamefile','localFile'),help='get a file from the remote database server')
	PPdbmsLob.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.17- Parent parser: usernamelikepassword
	PPusernamelikepassword = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPusernamelikepassword._optionals.title = "usernamelikepassword commands"
	PPusernamelikepassword.add_argument('--run',dest='run',action='store_true',required=True,help='try to connect using each Oracle username like the password')
	PPusernamelikepassword.add_argument('--force-retry',dest='force-retry',action='store_true',help='allow to test multiple passwords for a user without ask you')
	#1.18- Parent parser: smb
	PPsmb = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPsmb._optionals.title = "smb commands"
	PPsmb.add_argument('--capture',dest='captureSMBAuthentication',default=None,required=False,nargs=2,metavar=('local_ip','share_name'),help='capture the smb authentication')
	PPsmb.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.19- Parent parser: search
	PPsearch = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPsearch._optionals.title = "search commands"
	PPsearch.add_argument('--column-names',dest='column-names',default=None,required=False,metavar='sqlPattern',help='search pattern in all collumns')
	PPsearch.add_argument('--pwd-column-names',dest='pwd-column-names',action='store_true',help='search password patterns in all collumns')
	PPsearch.add_argument('--show-empty-columns',dest='show-empty-columns',action='store_true',help='show columns even if columns are empty')
	PPsearch.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.20- Parent parser: unwrapper
	PPunwrapper = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPunwrapper._optionals.title = "unwrapper commands"
	PPunwrapper.add_argument('--object-name',dest='object-name',default=None,required=False,help='unwrap this object stored in the database')
	PPunwrapper.add_argument('--file',dest='file',default=None,required=False,help='unwrap the source code stored in a file')
	PPunwrapper.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.21- Parent parser: clean
	PPclean = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=MAX_HELP_POSITION))
	PPclean._optionals.title = "clean commands"
	PPclean.add_argument('--all',dest='all',action='store_true',required=True,help='clean all traces and logs stored locally')
	#2- main commands
	subparsers = parser.add_subparsers(help='\nChoose a main command')
	#2.a- Run all modules
	parser_all = subparsers.add_parser('all',parents=[PPoptional,PPconnection,PPallModule,PPoutput,PPsidguesser,PPpassguesser],help='to run all modules in order to know what it is possible to do')	
	parser_all.set_defaults(func=runAllModules,auditType='all')
	#2.b- tnscmd
	parser_tnscmd = subparsers.add_parser('tnscmd',parents=[PPoptional,PPconnection,PPTnsCmd,PPoutput],help='to communicate with the TNS listener')	
	parser_tnscmd.set_defaults(func=runTnsCmdModule,auditType='tnscmd')
	#2.b- SIDGuesser
	parser_sidGuesser = subparsers.add_parser('sidguesser',parents=[PPoptional,PPconnection,PPsidguesser,PPoutput],help='to know valid SIDs')
	parser_sidGuesser.set_defaults(func=runSIDGuesserModule,auditType='sidGuesser')
	#2.c- PasswordGuesser
	parser_passwordGuesser = subparsers.add_parser('passwordguesser',parents=[PPoptional,PPconnection,PPpassguesser,PPoutput],help='to know valid credentials')
	parser_passwordGuesser.set_defaults(func=runPasswordGuesserModule,auditType='passwordGuesser')
	#2.d- UTL_HTTP
	parser_utlhttp = subparsers.add_parser('utlhttp',parents=[PPoptional,PPconnection,PPutlhttp,PPoutput],help='to send HTTP requests or to scan ports')
	parser_utlhttp.set_defaults(func=runUtlHttpModule,auditType='utl_http')
	#2.e- HTTPURITYPE
	parser_httpuritype = subparsers.add_parser('httpuritype',parents=[PPoptional,PPconnection,PPhttpuritype,PPoutput],help='to send HTTP requests or to scan ports')
	parser_httpuritype.set_defaults(func=runHttpUriTypeModule,auditType='httpuritype')
	#2.e- UTL_TCP
	parser_utltcp = subparsers.add_parser('utltcp',parents=[PPoptional,PPconnection,PPutltcp,PPoutput],help='to scan ports')
	parser_utltcp.set_defaults(func=runUtlTcpModule,auditType='utltcp')
	#2.f- CTXSYS
	parser_ctxsys = subparsers.add_parser('ctxsys',parents=[PPoptional,PPconnection,PPctxsys,PPoutput],help='to read files')
	parser_ctxsys.set_defaults(func=runCtxsysModule,auditType='ctxsys')
	#2.g- EXTERNAL TABLE
	parser_externaltable = subparsers.add_parser('externaltable',parents=[PPoptional,PPconnection,PPexternaltable,PPoutput],help='to read files or to execute system commands/scripts')
	parser_externaltable.set_defaults(func=runExternalTableModule,auditType='externaltable')
	#2.h- DBMS_XSLPROCESSOR
	parser_dbmsxslprocessor = subparsers.add_parser('dbmsxslprocessor',parents=[PPoptional,PPconnection,PPdbmsxslprocessor,PPoutput],help='to upload files')
	parser_dbmsxslprocessor.set_defaults(func=runDbmsXslprocessorModule,auditType='dbmsxslprocessor')
	#2.i- DBMSADVISOR
	parser_dbmsadvisor = subparsers.add_parser('dbmsadvisor',parents=[PPoptional,PPconnection,PPdbmsadvisor,PPoutput],help='to upload files')
	parser_dbmsadvisor.set_defaults(func=runDbmsadvisorModule,auditType='dbmsadvisor')
	#2.j- UTL_FILE
	parser_utlfile = subparsers.add_parser('utlfile',parents=[PPoptional,PPconnection,PPutlfile,PPoutput],help='to download/upload/delete files')
	parser_utlfile.set_defaults(func=runUtlFileModule,auditType='utlfile')
	#2.k- DBMSSCHEDULER
	parser_dbmsscheduler = subparsers.add_parser('dbmsscheduler',parents=[PPoptional,PPconnection,PPdbmsscheduler,PPoutput],help='to execute system commands without a standard output')
	parser_dbmsscheduler.set_defaults(func=runDbmsSchedulerModule,auditType='dbmsscheduler')
	#2.l- JAVA
	parser_java = subparsers.add_parser('java',parents=[PPoptional,PPconnection,PPjava,PPoutput],help='to execute system commands')
	parser_java.set_defaults(func=runjavaModule,auditType='java')
	#2.m- Passwords
	parser_passwords = subparsers.add_parser('passwordstealer',parents=[PPoptional,PPconnection,PPpasswords,PPoutput],help='to get hashed Oracle passwords')
	parser_passwords.set_defaults(func=runPasswordsModule,auditType='passwords')
	#2.n- Oradbg 
	parser_oradbg = subparsers.add_parser('oradbg',parents=[PPoptional,PPconnection,PPoradbg,PPoutput],help='to execute a bin or script')
	parser_oradbg.set_defaults(func=runOradbgModule,auditType='oradbg')
	#2.o- DBMS_LOB
	parser_dbmslob = subparsers.add_parser('dbmslob',parents=[PPoptional,PPconnection,PPdbmsLob,PPoutput],help='to download files')
	parser_dbmslob.set_defaults(func=runDbmsLob,auditType='dbmslob')
	#2.o- steal Passwords (CVE-2012-313)
	parser_passwords = subparsers.add_parser('stealremotepwds',parents=[PPoptional,PPstealRemotePass,PPoutput],help='to steal hashed passwords thanks an authentication sniffing (CVE-2012-3137)')
	parser_passwords.set_defaults(func=runCVE20123137Module,auditType='passwords')
	#2.p- username like password
	parser_usernamelikepassword = subparsers.add_parser('userlikepwd',parents=[PPoptional,PPconnection,PPusernamelikepassword,PPoutput],help='to try each Oracle username stored in the DB like the corresponding pwd')
	parser_usernamelikepassword.set_defaults(func=runUsernameLikePassword,auditType='usernamelikepassword')
	#2.q- smb
	parser_smb = subparsers.add_parser('smb',parents=[PPoptional,PPconnection,PPsmb,PPoutput],help='to capture the SMB authentication')
	parser_smb.set_defaults(func=runSMBModule,auditType='smb')
	#2.r- search
	parser_search = subparsers.add_parser('search',parents=[PPoptional,PPconnection,PPsearch,PPoutput],help='to search in databases, tables and columns')
	parser_search.set_defaults(func=runSearchModule,auditType='search')
	#2.s- PPunwrapper
	parser_unwrapper = subparsers.add_parser('unwrapper',parents=[PPoptional,PPconnection,PPunwrapper,PPoutput],help='to unwrap PL/SQL source code (no for 9i version)')
	parser_unwrapper.set_defaults(func=runUnwrapperModule,auditType='unwrapper')
	#2.t- clean
	parser_clean = subparsers.add_parser('clean',parents=[PPoptional,PPclean,PPoutput],help='clean traces and logs')
	parser_clean.set_defaults(func=runClean,auditType='clean')
	#3- parse the args
	if ARGCOMPLETE_AVAILABLE == True : argcomplete.autocomplete(parser)
	args = dict(parser.parse_args()._get_kwargs())
	arguments = parser.parse_args()
	#4- Configure logging and output
	configureLogging(args)
	args['print'] = Output(args)
	#5- define encoding
	reload(sys) 
	sys.setdefaultencoding(args['encoding'])
	#Start the good function
	if args['auditType']=='unwrapper' or args['auditType']=='clean': pass
	else:
		if ipOrNameServerHasBeenGiven(args) == False : return EXIT_MISS_ARGUMENT
	arguments.func(args)
	exit(ALL_IS_OK)


if __name__ == "__main__":
	main()


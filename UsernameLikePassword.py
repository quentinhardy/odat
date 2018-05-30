#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging,cx_Oracle
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser, getCredentialsFormated
from Constants import *
from PasswordGuesser import PasswordGuesser, runPasswordGuesserModule

class UsernameLikePassword (OracleDatabase):
	'''
	Allow to connect to the database using each Oracle username like the password 
	'''
	def __init__(self,args, lowerAndUpper=True):
		'''
		Constructor
		'''
		logging.debug("UsernameLikePassword object created")
		OracleDatabase.__init__(self,args)
		self.allUsernames = []
		self.validAccountsList = []
		self.lowerAndUpper=lowerAndUpper

	def __loadAllUsernames__(self):
		'''
		Get all usernames from the ALL_USERS table
		'''
		logging.info('Get all usernames from the ALL_USERS table')
		query = "select username from ALL_USERS"
		response = self.__execQuery__(query=query,ld=['username'])
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return response
		else :
			if response == []: self.allUsernames = []
			else:
				for e in response : self.allUsernames.append(e['username']) 
		logging.info("Oracle usernames stored in the ALL_USERS table: {0}".format(self.allUsernames))

	def tryUsernameLikePassword(self, additionalPwd=[]):
		'''
		Try to connect to the DB with each Oracle username using the username like the password
		if lowerAndUpper == True, the username in upper case and lower case format will be tested
		Otherwise identical to username only
		'''
		accounts = []
		self.__loadAllUsernames__()
		passwordGuesser = PasswordGuesser(self.args,accountsFile="",loginFile=None,passwordFile=None,loginAsPwd=False,timeSleep=self.args['timeSleep'])
		for usern in self.allUsernames:
			if self.lowerAndUpper == True:
				logging.debug("Password identical (upper case and lower case) to username will be tested for '{0}'".format(usern))
				accounts.append([usern,usern.upper()])
				accounts.append([usern,usern.lower()])
				logging.debug("These passwords will be tested for {0} also: {1}".format(usern, additionalPwd))
				for anAdditionalPwd in additionalPwd:
					accounts.append([usern,anAdditionalPwd])
			else:
				logging.debug("Password identical to username will be tested ONLY for '{0}' (option enabled)".format(usern))
				accounts.append([usern,usern])
		passwordGuesser.accounts = accounts
		passwordGuesser.searchValideAccounts()
		self.validAccountsList = passwordGuesser.valideAccounts	

	def testAll (self):
		'''
		Test all functions
		'''
		pass

def runUsernameLikePassword(args):
	'''
	Run the UsernameLikePassword module
	'''
	status= True
	usernameLikePassword = UsernameLikePassword(args)
	status = usernameLikePassword.connection(stopIfError=True)
	#Option 1: UsernameLikePassword
	if args['run'] !=None :
		additionalPwd = []
		args['print'].title("Oracle users have not the password identical to the username ?")
		if args.has_key('additional-pwd') and args['additional-pwd'] != None:
			additionalPwd = args['additional-pwd']
		usernameLikePassword.tryUsernameLikePassword(additionalPwd = additionalPwd)
		if usernameLikePassword.validAccountsList == {}:
			args['print'].badNews("No found a valid account on {0}:{1}/{2}".format(args['server'], args['port'], args['sid']))
		else :
			args['print'].goodNews("Accounts found on {0}:{1}/{2}: {3}".format(args['server'], args['port'], args['sid'],getCredentialsFormated(usernameLikePassword.validAccountsList)))


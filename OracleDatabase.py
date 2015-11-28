#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging, random, string, cx_Oracle
from Utils import areEquals,checkOracleVersion,getOracleConnection,ErrorSQLRequest
from progressbar import *
from time import sleep
from sys import exit
from Constants import *

class OracleDatabase:
	'''
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		self.args = args
		self.__generateConnectionString__()
		self.oracleDatabaseversion = ''
		self.remoteOS = ''
		self.TARGET_UNAVAILABLE = ["Connect failed because target host or object does not exist",
									"listener could not find available handler with matching protocol stack"]
		self.ERROR_BAD_FOLDER_OR_BAD_SYSTEM_PRIV = "ORA-29283: "
		self.ERROR_NO_PRIVILEGE = "ORA-24247: "
		self.ERROR_NO_PRIVILEGE_INVALID_ID = "ORA-00904: "
		self.ERROR_NOT_SYSDBA = "ORA-28009: "
		self.ERROR_INSUFF_PRIV_CONN = "ORA-01031: "
		self.ERROR_CONN_IMPOSS = "ORA-12541: "
		self.ERROR_XML_DB_SECU_NOT_INST = "ORA-24248: "
		self.ERROR_UNABLE_TO_ACQUIRE_ENV = "Unable to acquire Oracle environment handle"
		self.ERROR_NOT_CONNECTED = "ORA-03114: "

	def __generateConnectionString__(self):
		'''
		Generate Oracle Database connection string
		'''
		self.args['connectionStr'] = "{0}/{1}@{2}:{3}/{4}".format(self.args['user'],self.args['password'],self.args['server'],self.args['port'],self.args['sid'])
		logging.debug('Oracle connection string: {0}'.format(self.args['connectionStr']))
		return self.args['connectionStr']
	
	def connection(self,threaded =True, stopIfError=False):
		'''
		Connection to the database
		'The threaded argument is expected to be a boolean expression which indicates whether or not Oracle
		should use the mode OCI_THREADED to wrap accesses to connections with a mutex. Doing so in single threaded
		applications imposes a performance penalty of about 10-15% which is why the default is False.'
		If stopIfError == True, stop if connection error
		'''
		try: 
			if self.args['SYSDBA'] == True :
				self.args['dbcon'] = cx_Oracle.connect(self.args['connectionStr'], mode=cx_Oracle.SYSDBA,threaded=threaded)
			elif self.args['SYSOPER'] == True :	
				self.args['dbcon'] = cx_Oracle.connect(self.args['connectionStr'], mode=cx_Oracle.SYSOPER,threaded=threaded)
			else :
				self.args['dbcon'] = cx_Oracle.connect(self.args['connectionStr'],threaded=threaded)
			self.args['dbcon'].autocommit = True
			if self.remoteOS == '' and self.oracleDatabaseversion=='' : self.loadInformationRemoteDatabase() 
			return True
		except Exception, e:
			if self.ERROR_CONN_IMPOSS in str(e) or self.ERROR_UNABLE_TO_ACQUIRE_ENV in str(e):
				logging.critical("Impossible to connect to the remost host")
				exit(EXIT_BAD_CONNECTION)
			elif self.ERROR_NOT_SYSDBA in str(e): 
				logging.info("Connection as SYS should be as SYSDBA or SYSOPER, try to connect as SYSDBA")
				self.args['SYSDBA'] = True
				return self.connection(threaded=threaded, stopIfError=stopIfError)
			elif self.ERROR_INSUFF_PRIV_CONN in str(e):
				logging.info("Insufficient privileges, SYSDBA or SYSOPER disabled")
				self.args['SYSDBA'] = False
				self.args['SYSOPER'] = False
				return self.connection(threaded=threaded, stopIfError=stopIfError)
			elif stopIfError == True: 
				logging.critical("Impossible to connect to the remote database: {0}".format(self.cleanError(e)))
				exit(EXIT_BAD_CONNECTION)
			else : return ErrorSQLRequest(e)
		

	def __retryConnect__(self, nbTry=3):
		'''
		Try to re connect when TARGET UNAVAILABLE
		return status
		return None if impossible to connect to the database server
		'''
		timesleep, status = 2, ''
		for tryNum in range(nbTry):
			logging.debug("Re connection {0} to the listener on the {1} server".format(tryNum+1, self.args['server']))
			sleep(timesleep)
			status = self.connection()
			if self.__needRetryConnection__(status) == False:
				logging.debug("Re-connection done !")
				return status
			if tryNum == nbTry-1 :
				logging.warning("Becareful! The remote is now unavailable. {0} SID not tried. Perhaps you are doing a DOS on the listener.".format(self.args['sid']))
			timesleep += 4
			logging.debug("Impossible to re-establish the connection!")
		return None
	
	def __needRetryConnection__ (self, status):
		'''
		Return True if need retry the connection (server unaivalable)
		else return False
		'''
		for aString in self.TARGET_UNAVAILABLE:
			if aString in str(status):
				return True
		return False

	def close(self):
		'''
		Close connection to the database
		'''
		if self.args.has_key('dbcon'):
			try:
				self.args['dbcon'].close()
			except Exception, e:
				logging.debug("Impossible to close the connection to the database: {0}".format(e))

	def __execThisQuery__(self,query=None,ld=[],isquery=True):
		'''
		Permet de définir un cursor et execute la requete sql
		Si ld != [], active le chargement dans un dictionnaire des
		resultats
		'''
		cursor = self.args['dbcon'].cursor()
		try:
			if SHOW_SQL_REQUESTS_IN_VERBOSE_MODE == True: logging.info("SQL request executed: {0}".format(query))
			cursor.execute(query)
		except Exception, e:
			logging.info("Impossible to execute the query `{0}`: `{1}`".format(query, self.cleanError(e)))
			if self.ERROR_NOT_CONNECTED in str(e):
				status = self.__retryConnect__(nbTry=3)
				if status == None :
					return ErrorSQLRequest("Disconnected. Impossible to re-establish a connection to the database server !")
				else :
					return self.__execThisQuery__(query=query,ld=ld,isquery=isquery)
			else :
				return ErrorSQLRequest(e)
		if isquery==True :
			try :  
				results = cursor.fetchall()
			except Exception, e:
				logging.info("Impossible to fetch all the rows of the query {0}: `{1}`".format(query, self.cleanError(e)))
				return ErrorSQLRequest(e)
		else : 
			cursor.close()
			return 0
		cursor.close()
		if ld==[] : return results
		else :
			values = []
			for line in results:
					dico = {}
					for i in range(len(line)):
						dico[ld[i]] = line[i]
					values.append(dico)
			return values

	def __execPLSQL__(self,request):
		'''
		Execute this PL/SQL request
		'''
		return self.__execThisQuery__(query=request,ld=[],isquery=False)
		
	def __execQuery__(self,query,ld=[]):
		'''
		Execute the query (not PL/SQL) and parse response
		'''
		return self.__execThisQuery__(query=query, ld=ld, isquery=True)

	def __execProc__(self,proc,options=None):
		'''
		Execute the stored procedure
		'''
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try:
			if options == None :
				cursor.callproc(proc)
			else:
				cursor.callproc(proc,options)
		except Exception, e:
			logging.info("Impossible to execute the procedure `{0}`: {1}".format(proc, self.cleanError(e)))
			cursor.close()
			return ErrorSQLRequest(e)
		cursor.close()
		return True

	def __execPLSQLwithDbmsOutput__(self,request,addLineBreak=False):
		'''
		Execute the request containing dbms_output	
		'''
		responsedata = ""
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try : 		
			cursor.callproc("dbms_output.enable")
			try:
				cursor.execute(request)
			except Exception, e:
				logging.info("Impossible to execute the query `{0}`: {1}".format(request, self.cleanError(e)))
				return ErrorSQLRequest(e)
			else :
				statusVar = cursor.var(cx_Oracle.NUMBER)
				lineVar = cursor.var(cx_Oracle.STRING)
				while True:
					cursor.callproc("dbms_output.get_line", (lineVar, statusVar))
					if statusVar.getvalue() != 0:
						break
					line = lineVar.getvalue()
					if line == None : 
						line = ''
					responsedata += line
					if addLineBreak == True : responsedata +='\n'
				cursor.close()
		except Exception, e: 
			logging.info("Error with the request: {0}".format(str(e)))
			return ErrorSQLRequest(e)
		return responsedata

	def __generateRandomString__(self, nb=20):
		'''
		Generate a random string of nb chars
		'''	
		return ''.join(random.choice(string.ascii_uppercase) for x in range(nb))

	def __loadFile__(self, localFile):
		'''
		Return if it is a text file and return data stored in the localFile file
		If an error, return the error
		'''
		logging.debug("Loading the {0} file".format(localFile))
		data = ''
		try:
			f = open(localFile,'rb')
			data = f.read()
			f.close()
		except Exception, e: 
			logging.warning('Error during the read: {0}'.format(str(e)))
			return e
		return data
		
	def getStandardBarStarted(self, maxvalue):
		"""Standard status bar"""
		logging.debug("Creating a standard Bar with number of values = {0}".format(maxvalue))
		return ProgressBar(widgets=['', Percentage(), ' ', Bar(),' ', ETA(), ' ',''], maxval=maxvalue).start()

	def cleanError(self,errorMsg):
		'''
		Replace \n and \t by escape
		'''
		return str(errorMsg).replace('\n',' ').replace('\t',' ')

	def writeFile(self,nameFile, data):
		'''
		Write a new file named nameFile containing data
		Return True if Good, otherwise return False
		'''
		logging.info("Create the {0} file".format(nameFile))
		try:
			f = open(nameFile,'w')
			f.write(data)
			f.close()
		except Exception, e: 
			logging.warning('Error during the writing of the {0} file: {1}'.format(nameFile,self.cleanError(e)))
			return False
		return True

	def loadInformationRemoteDatabase(self):
		'''
		Get the oracle versions
		'''
		if 'dbcon' not in self.args :
			self.remoteOS = ""
			return False
		logging.debug ("Pickup the remote verion")
		self.oracleDatabaseversion = self.args['dbcon'].version
		logging.debug ("Pickup the remote Operating System")
		REQ = "select rtrim(substr(replace(banner,'TNS for ',''),1,instr(replace(banner,'TNS for ',''),':')-1)) os from v$version where  banner like 'TNS for %'"
		response = self.__execQuery__(query=REQ,ld=['OS'])
		if isinstance(response,Exception):
			return False
		else : 
			if isinstance(response,list) and isinstance(response[0],dict):
				self.remoteOS = response[0]['OS']
				logging.info("OS version : {0}".format(self.remoteOS))
				return True

	def remoteSystemIsWindows(self):	
		'''
		Return True if Windows
		'''
		if "windows" in self.remoteOS.lower() : return True
		else : return False

	def remoteSystemIsLinux(self):	
		'''
		Return True if Linux
		'''
		if "linux" in self.remoteOS.lower() or 'solaris' in self.remoteOS.lower() : return True
		else : return False

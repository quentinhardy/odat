#!/usr/bin/python
# -*- coding: utf-8 -*-

from DirectoryManagement import DirectoryManagement
import logging,cx_Oracle
#from OracleDatabase import OracleDatabase
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser
from Constants import *

class DbmsLob (DirectoryManagement):	
	'''
	Allow the user to read file thanks to DBMS_LOB
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("DbmsLob object created")
		DirectoryManagement.__init__(self,args)
		self.__setDirectoryName__()
		
	def getFile (self,remotePath, remoteNameFile, localFile):
		'''
		Create the localFile file containing data stored on the remoteNameFile (stored in the remotePath)
		'''
		data = ""
		logging.info("Copy the {0} remote file (stored in {1}) to {2}".format(remoteNameFile,remotePath,localFile))
		#Get data of the remote file
		DBMS_LOB_GET_FILE ="""
		DECLARE	
                        -- Pointer to the BFILE
                        l_loc       BFILE;
                        -- Current position in the file (file begins at position 1)
                        l_pos       NUMBER := 1;
                        -- Amount of characters to read
                        l_sum       BINARY_INTEGER;
                        -- Read Buffer
                        l_buf       VARCHAR2(32767);
			l_stat		BINARY_INTEGER := 16383;
                BEGIN
                        l_loc := BFILENAME('{0}','{1}');
                        DBMS_LOB.OPEN(l_loc,DBMS_LOB.LOB_READONLY);
			l_sum := dbms_lob.getlength(l_loc);
			LOOP
			IF (l_sum < 16383) THEN
				DBMS_LOB.READ(l_loc,l_sum,l_pos,l_buf);
				dbms_output.put_line(UTL_RAW.CAST_TO_VARCHAR2(l_buf));     	
				EXIT;
			END IF;
			l_sum := l_sum - 16383;
			DBMS_LOB.READ(l_loc,l_stat,l_pos,l_buf);
			l_pos := l_pos + 16383;
			dbms_output.put_line(UTL_RAW.CAST_TO_VARCHAR2(l_buf));
                        END LOOP;
                        DBMS_LOB.CLOSE(l_loc);
                END;
		"""
		isFileExist= self.getFileExist (remotePath, remoteNameFile)
		if isFileExist == True :
			status = self.__createOrRemplaceDirectory__(remotePath)
			if isinstance(status,Exception): return status
			cursor = cx_Oracle.Cursor(self.args['dbcon'])
			cursor.callproc("dbms_output.enable")
			try:
				cursor.execute(DBMS_LOB_GET_FILE.format(self.directoryName, remoteNameFile))
			except Exception, e:
				logging.info("Impossible to execute the query `{0}`: {1}".format(DBMS_LOB_GET_FILE, self.cleanError(e)))
				self.__dropDirectory__()
				return ErrorSQLRequest(e)
			else :
				statusVar = cursor.var(cx_Oracle.NUMBER)
				lineVar = cursor.var(cx_Oracle.STRING)
				while True:
					cursor.callproc("dbms_output.get_line", (lineVar, statusVar))
					if statusVar.getvalue() != 0: break
					line = lineVar.getvalue()
					if line == None : line = ''
					data += line
					logging.info(line)
			cursor.close()
		elif isFileExist == False : data = False
		else : data = isFileExist
		self.__dropDirectory__()
		return data
		
	def getFileExist (self, remotePath, remoteNameFile):
		'''
		Return true if file exists
		'''
		exist, returnedValue = False, False
		logging.info("Test if the {1}{0} file exists".format(remoteNameFile,remotePath))
		self.__setDirectoryName__()
		status = self.__createOrRemplaceDirectory__(remotePath)
		if isinstance(status,Exception): return status
		DBMS_LOB_FILE_EXISTS = "DECLARE l_loc BFILE; l_ret BOOLEAN := FALSE; BEGIN l_loc := BFILENAME('{0}','{1}'); l_ret := DBMS_LOB.FILEEXISTS(l_loc) = 1; IF (l_ret) THEN dbms_output.put_line('True'); ELSE dbms_output.put_line('False'); END IF;END;"
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try :
			cursor.callproc("dbms_output.enable")
			try:
				cursor.execute(DBMS_LOB_FILE_EXISTS.format(self.directoryName, remoteNameFile))
			except Exception, e:
				logging.info("Impossible to execute the query `{0}`: {1}".format(DBMS_LOB_FILE_EXISTS, self.cleanError(e)))
				returnedValue = ErrorSQLRequest(e)
			else :
				statusVar = cursor.var(cx_Oracle.NUMBER)
				lineVar = cursor.var(cx_Oracle.STRING)
				cursor.callproc("dbms_output.get_line", (lineVar, statusVar))
				if statusVar.getvalue() != 0: returnedValue = False
				line = lineVar.getvalue()
				if line == None : 
					line = ''	
				if "True" in line : 
					logging.debug("The file exist: good news")
					returnedValue = True
				elif "False" in line :
					logging.debug("The file doesn't exist") 
					returnedValue = False
				else :
					logging.warning("Can't know if the file exist. There is an error: {0}".format(line)) 
					returnedValue = ErrorSQLRequest(line)
			cursor.close()
		except Exception, e: 
			returnedValue = ErrorSQLRequest(e)
		self.__dropDirectory__()
		return returnedValue
		
	def testAll(self):
		'''
		Test all functions
		'''
		folder = self.__generateRandomString__()	
		self.args['print'].subtitle("DBMS_LOB to read files ?")
		logging.info("Simulate the file reading in the {0} folder thanks to DBMS_LOB".format(folder))
		status = self.getFile (remotePath=folder, remoteNameFile='data.txt', localFile="test.txt")
		if status == True or status == False:
			self.args['print'].goodNews("OK")
		else : 
			self.args['print'].badNews("KO")
		
def runDbmsLob (args):
	'''
	Run the DbmsLob module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","getFile"]) == False : return EXIT_MISS_ARGUMENT
	dbmsLob = DbmsLob(args)
	status = dbmsLob.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the DbmsLob module can be used")
		status = dbmsLob.testAll()
	#Option 1: getFile
	if args['getFile'] != None:
		args['print'].title("Read the {0} file stored in the {1} path".format(args['getFile'][1],args['getFile'][0]))
		data = dbmsLob.getFile (remotePath=args['getFile'][0], remoteNameFile=args['getFile'][1], localFile=args['getFile'][2])
		if isinstance(data,Exception):
			args['print'].badNews("There is an error: {0}".format(data))
		elif data == False : args['print'].badNews("The {0} file in {1} doesn't exist".format(args['getFile'][1],args['getFile'][0]))
		elif data == '' : args['print'].badNews("The {0} file is empty".format(args['getFile']))
		else :
			args['print'].goodNews("Data stored in the {0} file sored in {1} (copied in {2} locally):\n{3}".format(args['getFile'][1],args['getFile'][0],args['getFile'][2],data))
		

		

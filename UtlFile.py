#!/usr/bin/python
# -*- coding: utf-8 -*-

from DirectoryManagement import DirectoryManagement
import logging, random, string, cx_Oracle
from hashlib import md5
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser
from Constants import *

class UtlFile (DirectoryManagement):
	'''
	Allow the user to read/write file on the remote database system with UTL_FILE
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("UtlFile object created")
		DirectoryManagement.__init__(self,args)

	def __createFile__(self,nameFile, data, appendMode=False):
		'''
		Create a file named nameFile in the directoryName directory containing data
		Return True if no error, otherwise return exception
		'''
		logging.debug('Create the {0} file remotly'.format(nameFile))
		strAddData = ""
		#2.a- Create the remote binary file if exist
		UTL_FILE_CREATE_FILE = "DECLARE fi UTL_FILE.FILE_TYPE; bu RAW(32766); BEGIN fi:=UTL_FILE.fopen('{0}','{1}','wb',32766); UTL_FILE.fclose(fi); END;"
		request = UTL_FILE_CREATE_FILE.format(self.directoryName, nameFile)
		response = self.__execPLSQL__(request)
		if isinstance(response,Exception):
			logging.info('Impossible to create  file with UTL_FILE: {0}'.format(self.cleanError(response)))
			return response
		#2.b- Append to the remote file
		UTL_FILE_CREATE_FILE = "DECLARE fi UTL_FILE.FILE_TYPE; bu RAW(32766); BEGIN bu:=hextoraw('{0}'); fi:=UTL_FILE.fopen('{1}','{2}','ab',32766); UTL_FILE.put_raw(fi,bu,TRUE); UTL_FILE.fclose(fi); END;"
		for aPart in [data[i:i+3000] for i in range(0, len(data), 3000)]:
			request = UTL_FILE_CREATE_FILE.format(aPart.encode("hex"), self.directoryName, nameFile)
			response = self.__execPLSQL__(request)
			if isinstance(response,Exception):
				logging.info('Impossible to append to the file: {0}'.format(self.cleanError(response)))
				return response
		return True

	def putFile (self,remotePath, remoteNameFile, localFile=None, data=None):
		'''
		Create the localFile file (named remoteNameFile) on the remote system in the remotePath directory
		Choice between localFile or data
		Return True if no error, otherwise return exception
		'''
		if (localFile == None and data==None) or (localFile != None and data!=None): 
			logging.critical("To put a file, choose between a localFile or data")
		if data==None : logging.info('Copy the {0} file to the {1} remote path like {2}'.format(localFile,remotePath,remoteNameFile))
		else : logging.info('Copy this data : `{0}` in the {2} in the {1} remote path'.format(data,remotePath,remoteNameFile))
		self.__setDirectoryName__()
		status = self.__createOrRemplaceDirectory__(remotePath)
		if isinstance(status,Exception): return status
		if localFile != None:
			data = self.__loadFile__(localFile)
		status = self.__createFile__(remoteNameFile, data)
		if isinstance(status,Exception): return status
		self.__dropDirectory__()
		return True

	def appendFile(self,remotePath, remoteNameFile, localFile=None, data=None):
		'''
		Append to the remoteNameFile file (on the remote system in the remotePath directory) data stored on the localFile file
		Return True if no error, otherwise return exception
		'''
		logging.info('Append data stored in the {0} file to the {1} file stored in {2}'.format(localFile,remoteNameFile,remotePath))
		if (localFile == None and data==None) or (localFile != None and data!=None): 
			logging.error("To append to a file, choose between a localFile or data")		
		self.__setDirectoryName__()
		self.__createOrRemplaceDirectory__(remotePath)
		if localFile != None:
			data = self.__loadFile__(localFile)
		self.__createFile__(remoteNameFile, data, appendMode=True)
		status = self.__dropDirectory__()
		if isinstance(status,Exception):
			return status
		return True

	def getFile2 (self, remotePath, remoteNameFile):
		'''
		Create the localFile file containing data stored on the remoteNameFile (stored in the remotePath)
		'''
		logging.info("Read the {0} remote file stored in {1}".format(remoteNameFile,remotePath))
		data = ""
		self.__setDirectoryName__()
		status = self.__createOrRemplaceDirectory__(remotePath)
		if isinstance(status,Exception): return status
		#Get data of the remote file
		UTL_FILE_GET_FILE = "DECLARE l_fileID UTL_FILE.FILE_TYPE; l_buffer VARCHAR2(32000); hexdata VARCHAR2(32000); BEGIN l_fileID := UTL_FILE.FOPEN ('{0}', '{1}', 'r', 32000); LOOP UTL_FILE.GET_LINE(l_fileID, l_buffer, 32000); select RAWTOHEX(l_buffer) into hexdata from dual; dbms_output.put_line(hexdata); END LOOP; EXCEPTION WHEN NO_DATA_FOUND THEN UTL_FILE.fclose(l_fileID); NULL; END;"
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try : 		
			cursor.callproc("dbms_output.enable")
			try:
				cursor.execute(UTL_FILE_GET_FILE.format(self.directoryName, remoteNameFile))
			except Exception, e:
				logging.info("Impossible to execute the query `{0}`: {1}".format(UTL_FILE_GET_FILE, self.cleanError(e)))
				self.__dropDirectory__()
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
					data += line.decode('hex')+'\n'
				cursor.close()
		except Exception, e: 
			self.__dropDirectory__()
			return ErrorSQLRequest(e)
		self.__dropDirectory__()
		return data

	def getFile (self, remotePath, remoteNameFile):
		'''
		return data stored in the remoteNameFile file of the remotePath path
		Return False if file not exist
		'''
		logging.info("Read the {0} remote file stored in {1}".format(remoteNameFile,remotePath))
		data, currentByte = "", 0
		self.__setDirectoryName__()
		status = self.__createOrRemplaceDirectory__(remotePath)
		if isinstance(status,Exception): return status
		#Get data of the remote file
		#UTL_FILE_GET_FILE = "DECLARE l_fileID UTL_FILE.FILE_TYPE; l_buffer VARCHAR2(32000); hexdata VARCHAR2(32000); l_exists BOOLEAN; l_file_length NUMBER; l_blocksize NUMBER; BEGIN UTL_FILE.fgetattr('{0}', '{1}', l_exists, l_file_length, l_blocksize); l_fileID := UTL_FILE.FOPEN ('{0}', '{1}', 'r', 1000); UTL_FILE.FSEEK(l_fileID,0,{2}); LOOP UTL_FILE.GET_LINE(l_fileID, l_buffer, 32000); select RAWTOHEX(l_buffer,{2}) into hexdata from dual; dbms_output.put_line(hexdata); END LOOP; EXCEPTION WHEN NO_DATA_FOUND THEN UTL_FILE.fclose(l_fileID); NULL; END;"
		UTL_FILE_GET_FILE = "DECLARE l_fileID UTL_FILE.FILE_TYPE; l_buffer VARCHAR2(5000); hexdata VARCHAR2(10000); BEGIN l_fileID := UTL_FILE.FOPEN ('{0}', '{1}', 'r', 5000); UTL_FILE.FSEEK(l_fileID,{2},0); UTL_FILE.GET_LINE(l_fileID, l_buffer, 5000); select RAWTOHEX(l_buffer) into hexdata from dual; dbms_output.put_line(hexdata); UTL_FILE.fclose(l_fileID); END;"				
		if self.getFileExist (remotePath, remoteNameFile) == True :	
			length = self.getLength (remotePath, remoteNameFile)
			if length <= 0:	
				pass
			else :
				cursor = cx_Oracle.Cursor(self.args['dbcon'])
				cursor.callproc("dbms_output.enable")
				while currentByte < length:
					try:
						cursor.execute(UTL_FILE_GET_FILE.format(self.directoryName, remoteNameFile,currentByte))
					except Exception, e:
						logging.info("Impossible to execute the query `{0}`: {1}".format(UTL_FILE_GET_FILE, self.cleanError(e)))
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
							data += line.decode('hex')+'\n'
							currentByte += len(line.decode('hex')+'\n')
							logging.info(line.decode('hex'))
				cursor.close()
		else : data = False
		self.__dropDirectory__()
		return data

	

	def getLength (self, remotePath, remoteNameFile):
		'''
		Get the file length. Return 0 if empty or
		'''
		logging.info("Get the file length of the {1}{0} file".format(remoteNameFile,remotePath))
		data = ""
		self.__setDirectoryName__()
		status = self.__createOrRemplaceDirectory__(remotePath)
		if isinstance(status,Exception): return status
		UTL_FILE_GET_LENGTH = "DECLARE l_fileID UTL_FILE.FILE_TYPE; l_value VARCHAR2(32000); l_exists BOOLEAN; l_file_length NUMBER; l_blocksize NUMBER; BEGIN UTL_FILE.fgetattr('{0}', '{1}', l_exists, l_file_length, l_blocksize); dbms_output.put_line(l_file_length); END;"		
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try : 	
			cursor.callproc("dbms_output.enable")
			try:
				cursor.execute(UTL_FILE_GET_LENGTH.format(self.directoryName, remoteNameFile))
			except Exception, e:
				logging.info("Impossible to execute the query `{0}`: {1}".format(UTL_FILE_GET_LENGTH, self.cleanError(e)))
				self.__dropDirectory__()
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
						line = '0'
					logging.info("The file length is: {0}".format(line))
					return int(line)
			cursor.close()
		except Exception, e: 
			self.__dropDirectory__()
			return ErrorSQLRequest(e)
		self.__dropDirectory__()
		return data

	def getFileExist (self, remotePath, remoteNameFile):
		'''
		Return true if file exists
		'''
		exist = False
		logging.info("Test if the {1}{0} file exists".format(remoteNameFile,remotePath))
		self.__setDirectoryName__()
		status = self.__createOrRemplaceDirectory__(remotePath)
		if isinstance(status,Exception): return status
		UTL_FILE_EXIST = "DECLARE l_fileID UTL_FILE.FILE_TYPE; l_value VARCHAR2(32000); l_exists BOOLEAN; l_file_length NUMBER; l_blocksize NUMBER; BEGIN UTL_FILE.fgetattr('{0}', '{1}', l_exists, l_file_length, l_blocksize); dbms_output.put_line(case when l_exists then 'True' else 'False' end); END;"		
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try :
			cursor.callproc("dbms_output.enable")
			try:
				cursor.execute(UTL_FILE_EXIST.format(self.directoryName, remoteNameFile))
			except Exception, e:
				logging.info("Impossible to execute the query `{0}`: {1}".format(UTL_FILE_EXIST, self.cleanError(e)))
				self.__dropDirectory__()
				return ErrorSQLRequest(e)
			else :
				statusVar = cursor.var(cx_Oracle.NUMBER)
				lineVar = cursor.var(cx_Oracle.STRING)
				while True:
					cursor.callproc("dbms_output.get_line", (lineVar, statusVar))
					if statusVar.getvalue() != 0: break
					line = lineVar.getvalue()
					if line == None : 
						line = ''	
					if "True" in line : 
						logging.debug("The file exist: good news")
						return True
					elif "False" in line :
						logging.debug("The file doesn't exist") 
						return False
					else : return ''
			cursor.close()
		except Exception, e: 
			self.__dropDirectory__()
			return ErrorSQLRequest(e)
		self.__dropDirectory__()
		return data

	def deleteFile (self,remotePath, remoteNameFile):
		'''
		Delete a remote file
		'''
		logging.info("Delete the {0} remote file stored in {1}".format(remoteNameFile,remotePath))
		self.__setDirectoryName__()
		status = self.__createOrRemplaceDirectory__(remotePath)
		if isinstance(status,Exception):
			logging.info("Impossible to delete the file: {0}".format(self.cleanError(response)))
			return status
		UTL_FILE_DELETE_FILE = "BEGIN UTL_FILE.FREMOVE ('{0}', '{1}'); END;"
		response =self.__execPLSQL__(UTL_FILE_DELETE_FILE.format(self.directoryName, remoteNameFile))
		if isinstance(response,Exception):
			logging.info("Impossible to delete the file: {0}".format(self.cleanError(response)))
			return response
		return True

	def testAll(self):
		'''
		Test all functions
		'''
		folder = self.__generateRandomString__()	
		self.args['print'].subtitle("UTL_FILE library ?")
		logging.info("Simulate the file creation in the {0} folder with UTL_FILE".format(folder))
		logging.info('The file is not created remotly because the folder should not exist')
		status = self.putFile (remotePath=folder, remoteNameFile='temp.txt', data="test")
		if status == True or self.ERROR_BAD_FOLDER_OR_BAD_SYSTEM_PRIV in str(status):
			self.args['print'].goodNews("OK")
		else : 
			self.args['print'].badNews("KO")			


def runUtlFileModule(args):
	'''
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","getFile",'putFile','removeFile']) == False : return EXIT_MISS_ARGUMENT
	utlFile = UtlFile(args)
	status = utlFile.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the UTL_FILE library can be used")
		status = utlFile.testAll()
	#Option 1: read file
	if args['getFile'] !=None :
		args['print'].title("Read the {0} file stored in {1} on the {2} server".format(args['getFile'][1],args['getFile'][0],args['server']))
		#fileExist = utlFile.getFileExist(args['getFile'][0], args['getFile'][1])
		length = utlFile.getLength(args['getFile'][0], args['getFile'][1])
		data = utlFile.getFile(args['getFile'][0], args['getFile'][1])
		if isinstance(data,Exception):
			args['print'].badNews("Impossible to read the {0} file: {1}".format(args['getFile'],data))
		else : 
			if data == False : args['print'].badNews("The {0} file in {1} doesn't exist".format(args['getFile'][1],args['getFile'][0]))
			elif data == '' : args['print'].badNews("The {0} file is empty".format(args['getFile']))
			else :
				args['print'].goodNews("Data stored in the {0} file sored in {1} (copied in {2} locally):\n{3}".format(args['getFile'][1],args['getFile'][0],args['getFile'][2],data))
				utlFile.writeFile(args['getFile'][2],data)
	#Option 2: put file
	if args['putFile'] !=None :
		args['print'].title("Put the {0} local file in the {1} folder like {2} on the {3} server".format(args['putFile'][2],args['putFile'][0],args['putFile'][1],args['server']))
		status = utlFile.putFile(args['putFile'][0], args['putFile'][1], localFile=args['putFile'][2])
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to put the {0} file: {1}".format(args['putFile'][2],status))
		else : 
			args['print'].goodNews("The {0} file was created on the {1} directory on the {2} server like the {3} file".format(args['putFile'][2], args['putFile'][0], args['server'],args['putFile'][1]))
	#Option 3: remove file
	if args['removeFile'] !=None :
		args['print'].title("Remove the {0} file stored in the {1} folder on the {2} server".format(args['removeFile'][1],args['removeFile'][0],args['server']))
		status = utlFile.deleteFile(args['removeFile'][0], args['removeFile'][1])
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to remove the {0} file: {1}".format(args['removeFile'][1],status ))
		else : 
			args['print'].goodNews("The {0} file was deleted on the {1} directory on the {2} server".format(args['removeFile'][1], args['removeFile'][0], args['server']))


			



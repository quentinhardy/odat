#!/usr/bin/python
# -*- coding: utf-8 -*-

from DirectoryManagement import DirectoryManagement
import logging, random, string 
from Utils import checkOptionsGivenByTheUser
from Constants import *

class DbmsXslprocessor (DirectoryManagement):	
	'''
	Allow the user to write file on the remote database system with DbmsXslprocessor
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("DbmsXslprocessor object created")
		DirectoryManagement.__init__(self,args)

	def putFile (self, remotePath, remoteNameFile, data=None, localFile=None):
		'''
		Put a file on the remote database server
		Exemple : CREATE OR REPLACE DIRECTORY XML_DIR AS 'C:\temp\';
		exec dbms_xslprocessor.clob2file('dede', 'XML_DIR','outfile.txt');
		'''
		if (localFile == None and data==None) or (localFile != None and data!=None): 
			logging.critical("To put a file, choose between a localFile or data")
		if data==None : logging.info('Copy the {0} file to the {1} remote path like {2}'.format(localFile,remotePath,remoteNameFile))
		else : logging.info('Copy this data : `{0}` in the {2} in the {1} remote path'.format(data,remotePath,remoteNameFile))
		self.__setDirectoryName__()
		status = self.__createOrRemplaceDirectory__(remotePath)
		if isinstance(status,Exception): return status
		if localFile != None :
			data = self.__loadFile__(localFile)
		response = self.__execProc__("dbms_xslprocessor.clob2file",options=(data, self.directoryName, remoteNameFile))
		if isinstance(response,Exception):
			logging.info("Impossible to create a file with dbms_xslprocessor: {0}".format(self.cleanError(response)))
			return response
		return True

	def testAll (self):
		'''
		Test all functions
		'''
		folder = self.__generateRandomString__()	
		self.args['print'].subtitle("DBMS_XSLPROCESSOR library ?")
		logging.info("Simulate the file creation in the {0} folder with DBMS_XSLPROCESSOR".format(folder))
		logging.info('The file is not created remotly because the folder should not exist')
		status = self.putFile(folder,'temp.txt',data='data in file')
		if status == True or self.ERROR_BAD_FOLDER_OR_BAD_SYSTEM_PRIV in str(status) or self.ERROR_FILEOPEN_FAILED in str(status):
			self.args['print'].goodNews("OK")
		else : 
			self.args['print'].badNews("KO")

def runDbmsXslprocessorModule(args):
	'''
	Run the DbmsXslprocessor module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","putFile"]) == False : return EXIT_MISS_ARGUMENT
	dbmsXslprocessor = DbmsXslprocessor(args)
	status = dbmsXslprocessor.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the DBMSAdvisor library can be used")
		status = dbmsXslprocessor.testAll()
	#Option 1: putLocalFile
	if args['putFile'] != None:
		args['print'].title("Put the {0} local file in the {1} path (named {2}) of the {3} server".format(args['putFile'][2],args['putFile'][0],args['putFile'][1],args['server']))
		status = dbmsXslprocessor.putFile(args['putFile'][0], args['putFile'][1],localFile=args['putFile'][2])		
		if status == True:
			args['print'].goodNews("The {0} local file was put in the remote {1} path (named {2})".format(args['putFile'][2],args['putFile'][0],args['putFile'][1]))
		else :
			args['print'].badNews("The {0} local file was not put in the remote {1} path (named {2}): {3}".format(args['putFile'][2],args['putFile'][0],args['putFile'][1],str(status)))
	dbmsXslprocessor.close()

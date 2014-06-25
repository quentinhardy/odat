#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging

class DirectoryManagement(OracleDatabase):
	'''
	Allow to manage directories
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("DirectoryManagement object created")
		OracleDatabase.__init__(self,args)	
		self.PREFIX = "ODATPREFIX"
		#self.__dropAllOldDirectories__()
		self.__setDirectoryName__()

	def __setDirectoryName__(self):
		'''
		Generate a new directory name
		'''
		logging.debug('Generate a new directory name localy')
		self.directoryName = self.PREFIX + self.__generateRandomString__(nb=20).upper()

	def __createOrRemplaceDirectory__(self,path):
		'''
		Create a directory and grant READ,WRITE to PUBLIC
		Return True if no error, otherwise return exception
		'''
		logging.debug('Create or remplace the {0} directory to {1}'.format(self.directoryName, path))
		CREATE_REQUEST = "CREATE OR REPLACE DIRECTORY {0} AS '{1}'".format(self.directoryName, path)
		GRANT_REQUEST = "GRANT READ,WRITE ON DIRECTORY {0} TO PUBLIC".format(self.directoryName)
		response = self.__execPLSQL__(CREATE_REQUEST)
		if isinstance(response,Exception):
			logging.info("Impossible to create the directory: {0}".format(str(response).replace('\n',' ')))
			return response
		response = self.__execPLSQL__(GRANT_REQUEST)
		if isinstance(response,Exception):
			logging.info("Impossible to grant privileges on the directory: {0}".format(str(response).replace('\n',' ')))
			return response
		return True

	def __dropThisDirectory__(self, nameOfTheDirectory):
		'''
		Drop the directoryName directory 
		Return True if no error, otherwise return exception
		'''
		logging.debug('Drop the {0} directory'.format(nameOfTheDirectory))
		DROP_REQUEST = "DROP DIRECTORY {0}".format(nameOfTheDirectory)
		response = self.__execPLSQL__(DROP_REQUEST)
		if isinstance(response,Exception):
			logging.info("Impossible to drop the directory: {0}".format(str(response).replace('\n',' ')))
			return response
		return True

	def __dropDirectory__(self):
		'''
		Drop the directoryName directory 
		Return True if no error, otherwise return exception
		'''
		return self.__dropThisDirectory__(self.directoryName)

	def __dropAllOldDirectories__(self):
		'''
		Drop all directories created
		Return False if error
		Otherwise return True
		'''
		logging.debug('Drop all directories created')
		SELECT_REQ = "SELECT directory_name FROM all_directories WHERE directory_name LIKE '{0}%'".format(self.PREFIX)
		response = self. __execThisQuery__(query=SELECT_REQ,ld=['directory_name'])
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(SELECT_REQ,str(response)))
			return ErrorSQLRequest(response)
		if response == [] :
			logging.debug("No directory to delete")
			return True
		else :
			for aDir in response :
				self.__dropThisDirectory__(aDir['directory_name'])
			return True




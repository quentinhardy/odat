#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging

class Info (OracleDatabase):
	'''
	Information about the remote Oracle database
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("Info object created")
		OracleDatabase.__init__(self,args)
		self.version = ''
		self.os = ''

	def isVersion(self, version=None):
		'''
		return True if version 11
		'''
		if version in self.version : return True
		else: return False

	"""
	def loadInformationRemoteDatabase(self):
		'''
		Get the oracle versions
		'''
		logging.debug ("Pickup the remote verion")
		self.version = self.args['dbcon'].version
		logging.debug ("Getting remote Operating System")
		REQ = "select rtrim(substr(replace(banner,'TNS for ',''),1,instr(replace(banner,'TNS for ',''),':')-1)) os from v$version where  banner like 'TNS for %'"
		response = self.__execQuery__(query=REQ,ld=['OS'])
		if isinstance(response,Exception):
			pass
		else : 
			if isinstance(response,list) and len(response)>0 and isinstance(response[0],dict):
				self.os = response[0]['OS']
				logging.debug ("Remote Operating System")
		logging.info(str(self))
	"""
		
	def __str__(self):
		'''
		String representation
		'''
		return "Oracle Version: {0} and OS Version: {1}".format(self.version,self.os)

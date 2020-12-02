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
		
	def __str__(self):
		'''
		String representation
		'''
		return "Oracle Version: {0} and OS Version: {1}".format(self.version,self.os)

#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging

class SMB (OracleDatabase):
	'''
	Allow the database to connect to a smb share
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("SMB object created")
		OracleDatabase.__init__(self,args)

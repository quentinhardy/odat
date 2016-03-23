#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging, subprocess
from threading import Thread
from Utils import checkOptionsGivenByTheUser
from Constants import *

import re, base64, zlib, sys

class Unwrapper (OracleDatabase):
	'''
	To unwrap PL/SQL source code
	'''
	
	CHAR_MAP_SUBSTITUTION = [0x3d, 0x65, 0x85, 0xb3, 0x18, 0xdb, 0xe2, 0x87, 0xf1, 0x52, 0xab, 0x63, 0x4b, 0xb5, 0xa0, 0x5f, 0x7d, 0x68, 0x7b, 0x9b, 0x24, 0xc2, 0x28, 0x67, 0x8a, 0xde, 0xa4, 0x26, 0x1e, 0x03, 0xeb, 0x17, 0x6f, 0x34, 0x3e, 0x7a, 0x3f, 0xd2, 0xa9, 0x6a, 0x0f, 0xe9, 0x35, 0x56, 0x1f, 0xb1, 0x4d, 0x10, 0x78, 0xd9, 0x75, 0xf6, 0xbc, 0x41, 0x04, 0x81, 0x61, 0x06, 0xf9, 0xad, 0xd6, 0xd5, 0x29, 0x7e, 0x86, 0x9e, 0x79, 0xe5, 0x05, 0xba, 0x84, 0xcc, 0x6e, 0x27, 0x8e, 0xb0, 0x5d, 0xa8, 0xf3, 0x9f, 0xd0, 0xa2, 0x71, 0xb8, 0x58, 0xdd, 0x2c, 0x38, 0x99, 0x4c, 0x48, 0x07, 0x55, 0xe4, 0x53, 0x8c, 0x46, 0xb6, 0x2d, 0xa5, 0xaf, 0x32, 0x22, 0x40, 0xdc, 0x50, 0xc3, 0xa1, 0x25, 0x8b, 0x9c, 0x16, 0x60, 0x5c, 0xcf, 0xfd, 0x0c, 0x98, 0x1c, 0xd4, 0x37, 0x6d, 0x3c, 0x3a, 0x30, 0xe8, 0x6c, 0x31, 0x47, 0xf5, 0x33, 0xda, 0x43, 0xc8, 0xe3, 0x5e, 0x19, 0x94, 0xec, 0xe6, 0xa3, 0x95, 0x14, 0xe0, 0x9d, 0x64, 0xfa, 0x59, 0x15, 0xc5, 0x2f, 0xca, 0xbb, 0x0b, 0xdf, 0xf2, 0x97, 0xbf, 0x0a, 0x76, 0xb4, 0x49, 0x44, 0x5a, 0x1d, 0xf0, 0x00, 0x96, 0x21, 0x80, 0x7f, 0x1a, 0x82, 0x39, 0x4f, 0xc1, 0xa7, 0xd7, 0x0d, 0xd1, 0xd8, 0xff, 0x13, 0x93, 0x70, 0xee, 0x5b, 0xef, 0xbe, 0x09, 0xb9, 0x77, 0x72, 0xe7, 0xb2, 0x54, 0xb7, 0x2a, 0xc7, 0x73, 0x90, 0x66, 0x20, 0x0e, 0x51, 0xed, 0xf8, 0x7c, 0x8f, 0x2e, 0xf4, 0x12, 0xc6, 0x2b, 0x83, 0xcd, 0xac, 0xcb, 0x3b, 0xc4, 0x4e, 0xc0, 0x69, 0x36, 0x62, 0x02, 0xae, 0x88, 0xfc, 0xaa, 0x42, 0x08, 0xa6, 0x45, 0x57, 0xd3, 0x9a, 0xbd, 0xe1, 0x23, 0x8d, 0x92, 0x4a, 0x11, 0x89, 0x74, 0x6b, 0x91, 0xfb, 0xfe, 0xc9, 0x01, 0xea, 0x1b, 0xf7, 0xce]
	REQ_GET_SOURCE_CODE = "SELECT text, owner FROM all_source WHERE name LIKE '{0}' ORDER BY line" #{0} name; {1}
	REQ_GET_SOURCE_CODE_WITH_TYPE = "SELECT text, owner FROM all_source WHERE name LIKE '{0}' and type='{1}' ORDER BY line" #{0} name; {1} type of object
	
	def __init__(self,args, offline):
		'''
		Constructor
		'''
		logging.debug("Unwrapper object created")
		self.offline = offline
		if offline == False:
			logging.debug("Offline mode of Unwrapper module enabled.")
			OracleDatabase.__init__(self,args)
		else:
			logging.debug("Offline mode of Unwrapper module disabled")
		
	def __getSourceCode__ (self, objectName, objectType):
		'''
		returns souce code of the object objectName
		returns {'owner':'', 'sourceCode':''} or None if no result
		'''
		sourceCode = ""
		logging.info("Geeting the source code of the object named {0} (type={1})".format(objectName, objectType))
		if objectType == None:
			request = self.REQ_GET_SOURCE_CODE.format(objectName)
		else:
			request = self.REQ_GET_SOURCE_CODE_WITH_TYPE.format(objectName, objectType)
		logging.debug("Sending this request: {0}".format(request))
		results = self.__execQuery__(query=request, ld=['text', 'owner'])
		if results == []:
			logging.error('Empty response: No source code for the object named {0}. Perhaps a mistake in your object name'.format(objectName))
			return None
		else:
			for aResult in results: sourceCode += aResult['text']
			return {'owner':results[0]['owner'],'sourceCode':sourceCode}
			
	def __unwrap__ (self, wrappedCode):
		'''
		Returns PL/SQL data unwrapped or None if error
		'''
		logging.info("Unwrapping the following PL/SQL source code: '{0}'".format(wrappedCode))
		lines = wrappedCode['sourceCode'].split('\n')[:-1]
		try:
			for i in range(0, len(lines)):
				matches = re.compile(r"^[0-9a-f]+ ([0-9a-f]+)$").match(lines[i])
				if matches:
					b64str, j = '', 0
					b64len = int(matches.groups()[0], 16) 
					logging.debug("Length of base 64 string equal to {0}".format(b64len))
					while len(b64str) < b64len:
						j+=1
						b64len-=1
						b64str += lines[i+j]
					return(self.__decodeBase64Package__(b64str))
		except Exception,e:
			logging.error("Impossible to parse the correctly the PL/SQL source code: '{0}'".format(e)) 
		return None
		
	def unwrapRemotely(self, objectName, objectType):
		'''
		unwrap a PL/SQL code remotely
		Returns Nne if error. Otherwise returns source code unwrapped
		'''
		sourceCode = self.__getSourceCode__(objectName, objectType)
		if sourceCode == None: return None
		code = self.__unwrap__(sourceCode)
		return code
		
	def unwrapLocally(self, filename):
		'''
		unwrap a PL/SQL code remotely
		'''
		f = open(filename)
		lines = "".join(f.readlines())
		code = self.__unwrap__({'owner':'unknown', 'sourceCode':lines})
		return code
	
		
	def __decodeBase64Package__(self,b64str):
		'''
		Return None if error
		'''
		decoded = ''
		try:
			b64dec = base64.decodestring(b64str)[20:] # we strip the first 20 chars (SHA1 hash, I don't bother checking it at the moment)
			for byte in range(0, len(b64dec)): decoded += chr(self.CHAR_MAP_SUBSTITUTION[ord(b64dec[byte])])
			datadec = zlib.decompress(decoded)
		except Exception,e:
			logging.error("Impossible to decompress data: '{0}'".format(e)) 
			return None
		return datadec
			
	def testAll (self):
		'''
		Test all functions
		'''
		self.args['print'].subtitle("Unwrap PL/SQL source code remotely?")
		logging.info('Nothing to do, return True')
		self.args['print'].goodNews("OK")
		return True

def runUnwrapperModule(args):
	'''
	Run the unwrapper module
	'''
	status, offline = True, True
	if args['test-module'] == False and args['object-name'] == None and args['file'] == None:
		logging.critical("You must choose --test-module or/and --object-name or/and --file")
		return EXIT_MISS_ARGUMENT
	if args['test-module'] == True :
		args['print'].title("Test if the Unwrapper module can be used")
		unwrapper = Unwrapper(args, offline=False)
		unwrapper.testAll()
	if args['file'] != None:
		offline = True
		unwrapper = Unwrapper(args, offline=True)
	if args['object-name'] != None:
		if checkOptionsGivenByTheUser(args,["test-module","object-name"]) == False : return EXIT_MISS_ARGUMENT
		offline = False
		unwrapper = Unwrapper(args, offline=False)
		unwrapper.connection(stopIfError=True)
	#if args['object-name'] != None :
		args['print'].title("Unwrapping PL/SQL source code of {0} stored in the remote database".format(args['object-name']))
		code = unwrapper.unwrapRemotely(args['object-name'], objectType = args['object-type'])
		if code == None: args['print'].badNews("Impossible to get the source code or to unwrap it. Is it wrapped? Have you permissions?...")
		else: args['print'].goodNews(code)
	if args['file'] != None :
		args['print'].title("Unwrapping PL/SQL source code stored in the local file named {0}".format(args['file']))
		code = unwrapper.unwrapLocally(args['file'])
		if code == None: args['print'].badNews("Impossible to read the source code or to unwrap it. Is it wrapped? Have you permissions?...")
		else: args['print'].goodNews(code)
	
	
	
	

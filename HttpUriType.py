#!/usr/bin/python
# -*- coding: utf-8 -*-

from Http import Http
import logging
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser
from Constants import *


class HttpUriType (Http):
	'''
	Allow the user to send HTTP request
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("HttpUriType object created")
		Http.__init__(self,args)

	def sendGetRequest(self,url,printResponse=True):
		'''
		Send a HTTP get request to url
		Return False if the current user is not allowed to use the httpuritype lib, else return False or response data
		'''
		logging.info('Send a HTTP GET request to {0}'.format(url))
		query = "select httpuritype('{0}').getclob() from dual".format(url)
		response = self.__execQuery__(query=query,ld=['data'])
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return response
		elif isinstance(response,list) and isinstance(response[0],dict):
			return response[0]['data']
		logging.info('Enough privileges')
		return ''

	def testAll (self):
		'''
		Test all functions
		'''
		self.args['print'].subtitle("HTTPURITYPE library ?")
		logging.info('Try to make the server send a HTTP request to 0.0.0.0 with the HTTPURITYPE library')
		response = self.sendGetRequest('http://0.0.0.0/',printResponse=False)
		if isinstance(response,Exception) and self.ERROR_NO_PRIVILEGE in str(response) or self.ERROR_XML_DB_SECU_NOT_INST in str(response):
				logging.info('Not enough privileges: {0}'.format(str(response)))
				self.args['print'].badNews("KO")
				return False
		else:
			self.args['print'].goodNews("OK")
			return True

def runHttpUriTypeModule(args):
	'''
	Run the HTTPURITYPE module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","httpUrl","scan-ports"]) == False : return EXIT_MISS_ARGUMENT
	httpUriType = HttpUriType(args)
	status = httpUriType.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the HTTPURITYPE library can be used")
		status = httpUriType.testAll()
	#Option 1: httpUrl
	if args['httpUrl'] != None:
		args['print'].title("Send a GET request from {0} to {1}".format(args['connectionStr'],args['httpUrl']))
		response = httpUriType.sendGetRequest(url=args['httpUrl'])
		if isinstance(response,Exception):
			args['print'].badNews("HTTP GET request failed")
		else :
			args['print'].goodNews("The server response is:\n {0}".format(response))
			if args['outputFile'] != None : httpUriType.writeFile(args['outputFile'],str(response))
	#Option 2: scan-ports
	if args['scan-ports'] != None:
		ports = []
		if "," in args['scan-ports'][1]: ports=args['scan-ports'][1].split(',')
		elif '-' in args['scan-ports'][1]:
			startEnd = args['scan-ports'][1].split('-')
			for aPort in range(int(startEnd[0]),int(startEnd[1])): ports.append(str(aPort))
			if ports == []:
				logging.critical("The second parameter ('{0}') is not a valid: cancelation...".format(args['scan-ports'][1]))
				return -1
		else : 
			if args['scan-ports'][1].isdigit() == True: 
				ports = [args['scan-ports'][1]]
			else: 
				logging.critical("The second parameter ('{0}') is not a valid port: cancelation...".format(args['scan-ports'][1]))
				return -1
		args['print'].title("Scan ports ({0}) of {1} ".format(args['scan-ports'][1],args['scan-ports'][0]))
		resultats = httpUriType.scanTcpPorts(httpObject=httpUriType,ip=args['scan-ports'][0],ports=ports)
		httpUriType.printScanPortResults(resultats)
	httpUriType.close()



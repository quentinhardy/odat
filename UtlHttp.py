#!/usr/bin/python
# -*- coding: utf-8 -*-

from Http import Http
import logging
from sys import exit
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser
from Constants import *

class UtlHttp (Http):
	'''
	Allow the user to send HTTP request
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("UtlHttp object created")
		Http.__init__(self,args)

	def setTimeout(self,value):
		'''
		Set the timeout value with utl_http.set_transfer_timeout(value)	
		Default value = 60 s in oracle
		Return True si Ok, otherwise return the Exception
		'''
		status = self.__execProc__('utl_http.set_transfer_timeout',options=[value])
		if isinstance(status,Exception):
			logging.warning("Impossible to set the timeout value: {0}".format(self.cleanError(status)))
			return status
		else :
			logging.info('The timeout value is turned on {0} secs'.format(value))	
			return True

	def sendGetRequest(self,url):
		'''
		send a HTTP get request to url
		Return False if the current user is not allowed to use the httpuritype lib, else return False or response data
		'''
		logging.info('Send a HTTP GET request to {0}'.format(url))

		query = "select utl_http.request('{0}') as data from dual".format(url)
		response = self. __execThisQuery__(query=query,ld=['data'])
		if isinstance(response,Exception):
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return ErrorSQLRequest(response)
		elif isinstance(response,list) and isinstance(response[0],dict):
			return response[0]['data']
		logging.info('Enough privileges')
		return ''

	def sendRequest(self,ip,port,filename):
		'''
		'''
		params = self.parseRequest(nameFileRequest=filename)
		if params == None : return False
		request = "DECLARE req utl_http.req; res utl_http.resp; buffer varchar2(4000); BEGIN req := utl_http.begin_request('http://{0}:{1}{2}', '{3}','{4}');".format(ip,port,params['url'],params['method'],params['version'])
		for key in params['header'].keys():
			request += "utl_http.set_header(req, '{0}','{1}');".format(key,params['header'][key])
		if params['body'] != None:
			request += "utl_http.write_text(req, '{0}');".format(params['body'])
		request += "res := utl_http.get_response(req); BEGIN LOOP utl_http.read_line(res, buffer); dbms_output.put_line(buffer); END LOOP; utl_http.end_response(res); exception when utl_http.end_of_body then utl_http.end_response(res); END; END;"
		response = self.__execPLSQLwithDbmsOutput__(request=request)
		return response

	def testAll (self):
		'''
		Test all functions
		'''
		self.args['print'].subtitle("UTL_HTTP library ?")
		logging.info('Try to make the server send a HTTP request to 0.0.0.0 with the UTL_HTTP library')
		response = self.sendGetRequest('http://0.0.0.0/')
		if isinstance(response,Exception) and self.ERROR_NO_PRIVILEGE in str(response) or self.ERROR_NO_PRIVILEGE_INVALID_ID in str(response) or self.ERROR_XML_DB_SECU_NOT_INST in str(response): #ERROR_NO_PRIVILEGE_INVALID_ID ==> For Oracle 10g
				logging.info('Not enough privileges: {0}'.format(str(response)))
				self.args['print'].badNews("KO")
				return False
		else:
			self.args['print'].goodNews("OK")
			return True
			
def runUtlHttpModule(args):
	'''
	Run the UTL_HTTP module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","scan-ports","send"]) == False : return EXIT_MISS_ARGUMENT
	utlHttp = UtlHttp(args)
	status = utlHttp.connection(stopIfError=True)
	utlHttp.setTimeout(5)
	if args['test-module'] == True :
		args['print'].title("Test if the UTL_HTTP library can be used")
		status = utlHttp.testAll()
	#Option 1: sendRequest
	if args['send'] != None:
		args['print'].title("Send the HTTP request stored in the {0} file".format(args['send'][2]))
		data = utlHttp.sendRequest(args['send'][0],args['send'][1],args['send'][2])
		if isinstance(data,Exception): 
			args['print'].badNews("Impossible to send the request: {0}".format(data))
		else : 
			args['print'].goodNews("Response from the server:\n{0}".format(data))
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
		elif  args['scan-ports'][1].isdigit() == True: 
			ports = [args['scan-ports'][1]]
		else: 
			logging.critical("The second parameter ('{0}') is not a valid port: cancelation...".format(args['scan-ports'][1]))
			return -1
		args['print'].title("Scan ports ({0}) of {1} ".format(args['scan-ports'][1],args['scan-ports'][0]))
		resultats = utlHttp.scanTcpPorts(httpObject=utlHttp,ip=args['scan-ports'][0],ports=ports)
		utlHttp.printScanPortResults(resultats)
	utlHttp.close()


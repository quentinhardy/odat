#!/usr/bin/python
# -*- coding: utf-8 -*-

from Http import Http
import logging, cx_Oracle
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser
from Constants import *

import threading, thread

class UtlTcp (Http):
	'''
	Allow the user to scan ports
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("UtlTcp object created")
		Http.__init__(self,args)

	def tryToConnect(self,server,port):
		'''
		Try to connect to this server on the port selected
		'''
		request = "DECLARE c  utl_tcp.connection; BEGIN c := utl_tcp.open_connection('{0}',{1}); utl_tcp.close_connection(c); END;".format(server, port)
		response = self.__execPLSQL__(request)
		if isinstance(response,Exception):
			logging.info('Impossible to connect to the {0}:{1} server with UTL_TCP: {2}'.format(server,port,response))
			return response
		else : return True

	def sendPacket(self,server,port,filename=None, data=None):
		'''
		Send a packet to the server, on the specific port
		'''
		responsedata = ""
		if filename==None and data==None : logging.error("To send a packet via UTL_TCP, you must choose between a name file or data")
		if filename != None: data = self.__loadFile__(filename)
		elif data == None: data = ""
		data = data.encode("hex")
		request = "DECLARE c  utl_tcp.connection; ret_val pls_integer; bu RAW(32766); BEGIN c := utl_tcp.open_connection('{0}',{1}); bu:=hextoraw('{2}'); ret_val := utl_tcp.write_raw(c, bu); ret_val := utl_tcp.write_line(c); BEGIN LOOP dbms_output.put_line(utl_tcp.get_line(c, TRUE)); END LOOP; EXCEPTION WHEN utl_tcp.end_of_input THEN NULL; END; utl_tcp.close_connection(c); END;".format(server, port,data)
		logging.info("Send the packet")		
		data = self.__execPLSQLwithDbmsOutput__(request,addLineBreak=True)
		return data


	def testAll (self):
		'''
		Test all functions
		'''
		self.args['print'].subtitle("UTL_TCP library ?")
		logging.info('Try to make the server connect to 0.0.0.0:00 with the UTL_TCP library')
		response = self.tryToConnect('0.0.0.0','1')
		if isinstance(response,Exception) and self.ERROR_UTL_TCP_NETWORK not in str(response):
				logging.info('Not enough privileges: {0}'.format(str(response)))
				self.args['print'].badNews("KO")
				return False
		else:
			self.args['print'].goodNews("OK")
			return True

def runUtlTcpModule(args):
	'''
	Run the UTL_TCP module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","send-packet","scan-ports"]) == False : return EXIT_MISS_ARGUMENT
	utlTcp = UtlTcp(args)
	status = utlTcp.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the UTL_TCP library can be used")
		status = utlTcp.testAll()
	#Option 2: send packet
	if args['send-packet'] != None:
		args['print'].title("Send the packet stored in the {0} file".format(args['send-packet'][2]))
		data = utlTcp.sendPacket(args['send-packet'][0],args['send-packet'][1],filename=args['send-packet'][2])
		if isinstance(data,Exception): 
			args['print'].badNews("Impossible to send the packet: {0}".format(data))
		else : 
			args['print'].goodNews("Response from the server:\n{0}".format(data))
	#Option 1: tcp Scan
	if args['scan-ports'] != None:
		ports = []
		if "," in args['scan-ports'][1]: ports=args['scan-ports'][1].split(',')
		elif '-' in args['scan-ports'][1]:
			startEnd = args['scan-ports'][1].split('-')
			for aPort in range(int(startEnd[0]),int(startEnd[1])): ports.append(str(aPort))
		else : logging.error("Syntax for ports given not recognized")
		args['print'].title("Scan ports ({0}) of {1} ".format(args['scan-ports'][1],args['scan-ports'][0]))
		resultats = utlTcp.scanTcpPorts(httpObject=utlTcp,ip=args['scan-ports'][0],ports=ports)
		utlTcp.printScanPortResults(resultats)
	utlTcp.close()




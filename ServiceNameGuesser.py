#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
from time import sleep
from itertools import product
import logging, string
from Tnscmd import Tnscmd
from Constants import *
from Utils import stringToLinePadded

class ServiceNameGuesser (OracleDatabase):
	'''
	Service Name guesser
	'''
	def __init__(self, args, serviceNameFile, timeSleep=0):
		'''
		Constructor
		'''
		logging.debug("ServiceNameGuesser object created")
		OracleDatabase.__init__(self,args)
		self.serviceNameFile = serviceNameFile
		self.serviceNames = []
		self.validServiceNames = []
		self.args['SYSDBA'] = False
		self.args['SYSOPER'] = False
		self.timeSleep = timeSleep
		self.NO_GOOD_SERVICE_NAME_STRING_LIST = ["listener does not currently know of service requested",
												 "listener does not currently know of SID",
												 "connection to server failed"]

	def getValidServiceNames(self):
		'''
		return a list containing valid Service Names found
		'''
		return self.validServiceNames

	def appendValidServiceName (self, serviceName):
		'''
		Append to self.validServiceNames a new Service Name if no in the list
		'''
		if serviceName not in self.validServiceNames:
			self.validServiceNames.append(serviceName)

	def __getServiceNamesFromFile__(self):
		'''
		return list containing Service Names
		'''
		serviceNames = []
		logging.info('Load Service Names stored in the {0} file'.format(self.serviceNameFile))
		f = open(self.serviceNameFile)
		for l in f:
			serviceNames.append(l.replace('\n','').replace('\t',''))
		f.close()
		return sorted(serviceNames)

	def __testIfAGoodServiceName__(self):
		'''
		Test if it is a good Service Name
		'''
		no_good_service_name_found = False
		self.__generateConnectionString__(username=self.__generateRandomString__(nb=15), password=self.__generateRandomString__(nb=5))
		logging.debug("Try to connect with the {0} Service Name ({1})".format(self.args['serviceName'], self.args['connectionStr']))
		status = self.connection()
		if self.__needRetryConnection__(status) == True: 
			status = self.__retryConnect__(nbTry=4)
		if status != None :
			for aNoGoodString in self.NO_GOOD_SERVICE_NAME_STRING_LIST:
				if aNoGoodString in str(status):
					no_good_service_name_found = True
					break
			if no_good_service_name_found == False:
				self.appendValidServiceName(self.args['serviceName'])
				logging.info("'{0}' is a valid Service Name (Server message: {1})".format(self.args['serviceName'], str(status)))
				self.args['print'].goodNews(stringToLinePadded("'{0}' is a valid Service Name. Continue... ".format(self.args['serviceName'])))
		self.close()

	def searchKnownServiceNames(self):
		'''
		Search valid Service Names THANKS TO a well known Service Name list
		'''
		self.args['print'].subtitle("Searching valid Service Names thanks to a well known Service Name list on the {0}:{1} server".format(self.args['server'], self.args['port']))
		self.serviceNames += self.__getServiceNamesFromFile__()
		pbar,nb = self.getStandardBarStarted(len(self.serviceNames)), 0
		logging.info('Start the research')
		self.args['sid'] = None
		for aServiceName in self.serviceNames :
			nb += 1
			pbar.update(nb)
			self.args['serviceName'] = aServiceName
			
			self.__testIfAGoodServiceName__()

			sleep(self.timeSleep)
		pbar.finish()
		return True

	def bruteforceServiceNames(self, size=4, charset=string.ascii_uppercase):
		'''
		Bruteforce Service Names
		'''
		self.args['print'].subtitle("Searching valid Service Names thanks to a brute-force attack on {2} chars now ({0}:{1})".format(self.args['server'], self.args['port'], size))
		pbar,nb = self.getStandardBarStarted(len(charset)**size), 0
		logging.info('Start the research')
		self.args['sid'] = None
		for aServiceName in product(list(charset), repeat=size):
			nb +=1
			pbar.update(nb)
			self.args['serviceName'] = ''.join(aServiceName)

			self.__testIfAGoodServiceName__()

			sleep(self.timeSleep)
		pbar.finish()
		return True

	def loadServiceNameFromListenerAlias(self):
		'''
		Append ALIAS from listener into the Service Name list to try ALIAS like Service Name
		'''
		logging.info('Put listener ALIAS into the Service Name list to try ALIAS like Service Name')
		tnscmd = Tnscmd(self.args)
		tnscmd.getInformation()
		self.serviceNames += tnscmd.getAlias()

def runServiceNameGuesserModule(args):
	'''
	Run the ServiceNameGuesser module
	'''
	args['print'].title("Searching valid Service Names")
	serviceNameGuesser = ServiceNameGuesser(args, args['service-name-file'], timeSleep=args['timeSleep'])
	serviceNameGuesser.loadServiceNameFromListenerAlias()
	serviceNameGuesser.searchKnownServiceNames()
	for aServiceNameSize in range(args['service-name-min-size'], args['service-name-max-size']+1):
		serviceNameGuesser.bruteforceServiceNames(size=aServiceNameSize, charset=args['service-name-charset'])
	validServiceNameList = serviceNameGuesser.getValidServiceNames()
	if validServiceNameList == []:
		args['print'].badNews("No found a valid Service Name".format(args['server'], args['port']))
	else :
		args['print'].goodNews("Service Name(s) found on the {0}:{1} server: {2}".format(args['server'], args['port'], ','.join(validServiceNameList)))
	return validServiceNameList



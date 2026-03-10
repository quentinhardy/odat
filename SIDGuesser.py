#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
from time import sleep
from itertools import product
import logging, string
from Tnscmd import Tnscmd
from Constants import *
from Utils import stringToLinePadded
import re

class SIDGuesser (OracleDatabase):
	'''
	SID guesser
	'''
	def __init__(self, args, SIDFile, timeSleep=0):
		'''
		Constructor
		'''
		logging.debug("SIDGuesser object created")
		OracleDatabase.__init__(self,args)
		self.SIDFile = SIDFile
		self.sids = []
		self.valideSIDS = []
		self.args['SYSDBA'] = False
		self.args['SYSOPER'] = False
		self.timeSleep = timeSleep
		self.ORA_ERROR_NO_GOOD_SID = ["ORA-12514",#listener does not currently know of service requested
									"ORA-12505", #listener does not currently know of SID given in connect descriptor
									"TNS-12505", #listener does not currently know of SID given in connect descriptor
									"ORA-12521", #listener does not currently know of instance requested in connect descriptor
									"TNS-12521", #listener does not currently know of instance requested in connect descriptor
									"ORA-12520", #TNS:listener could not find available handler for requested type of server
									"ORA-12541", #TNS:no listener
									"ORA-12543", #destination host unreachable / unable to connect to destination
									"ORA-12545", #target host or object does not exist / name lookup style failure
									"ORA-12154", #TNS:could not resolve the connect identifier specified
									"ORA-28547", #connection to server failed
									"ORA-12543", #destination host unreachable
									"ORA-12504", #listener was not given the SERVICE_NAME in CONNECT_DATA
									"ORA-12757", #instance does not currently know of requested service
									"ORA-12516", #listener cannot find available handler
									"ORA-12519", #no appropriate service handler
									"ORA-12520", #no handler for requested server type
									]

	def getValidSIDs(self):
		'''
		return a list containing valid sids found
		'''
		return self.valideSIDS

	def appendValideSID (self, sid):
		'''
		Append to self.valideSIDS a new DIS if no in the list
		'''
		if sid not in self.valideSIDS:
			self.valideSIDS.append(sid)

	def __loadSIDsFromFile__(self):
		'''
		return list containing SIDS
		'''
		sids = []
		logging.info('Load SIDS stored in the {0} file'.format(self.SIDFile))
		f = open(self.SIDFile)
		for l in f:
			sids.append(l.replace('\n','').replace('\t',''))
		f.close()
		return sorted(sids)

	def __testIfAGoodSID__(self):
		'''
		Test if it is a good SID
		Return status of the connection
		'''
		no_good_sid_found = False
		self.args['serviceName'] = None
		self.__generateConnectionString__(username=self.__generateRandomString__(nb=15), password=self.__generateRandomString__(nb=5))
		logging.debug("Try to connect with the {0} SID ({1})".format(self.args['sid'], self.args['connectionStr']))
		status = self.connection()
		if self.__needRetryConnection__(status) == True: 
			status = self.__retryConnect__(nbTry=4)
		if status != None :
			for aNoGoodString in self.ORA_ERROR_NO_GOOD_SID:
				if aNoGoodString.upper() in str(status).upper():
					no_good_sid_found = True
					break
			if no_good_sid_found == False:
				self.appendValideSID(self.args['sid'])
				logging.info("'{0}' is a valid SID (Server message: {1})".format(self.args['sid'],str(status)))
				self.args['print'].goodNews(stringToLinePadded("'{0}' is a valid SID. Continue... ".format(self.args['sid'])))
		self.close()
		return status

	def searchKnownSIDs(self):
		'''
		Search valid SIDs THANKS TO a well known sid list
		Return False if connection error.
		Return True if SIDs have been tested.
		'''
		self.args['print'].subtitle("Searching valid SIDs thanks to a well known SID list on the {0}:{1} server".format(self.args['server'], self.args['port']))
		self.sids += self.__loadSIDsFromFile__()
		pbar,nb = self.getStandardBarStarted(len(self.sids)), 0
		logging.info('Start the research')
		for aSID in self.sids :
			nb += 1
			pbar.update(nb)
			self.args['sid'] = aSID
			
			connectionStatus = self.__testIfAGoodSID__()

			sleep(self.timeSleep)
		pbar.finish()
		return True

	def bruteforceSIDs(self, size=4, charset=string.ascii_uppercase):
		'''
		Bruteforce SID
		'''
		self.args['print'].subtitle("Searching valid SIDs thanks to a brute-force attack on {2} chars now ({0}:{1})".format(self.args['server'], self.args['port'], size))
		pbar,nb = self.getStandardBarStarted(len(charset)**size), 0
		logging.info('Start the research')
		for aSID in product(list(charset), repeat=size):
			nb +=1
			pbar.update(nb)
			self.args['sid'] = ''.join(aSID)

			self.__testIfAGoodSID__()

			sleep(self.timeSleep)
		pbar.finish()
		return True
		
	import re

	def _underscoreSIDSubstrings(self, value):
		'''
		Return all unique contiguous underscore-joined substrings from a string.
		Example:
			"LISTENER_A_DG"
		returns:
			[
				"LISTENER",
				"A",
				"DG",
				"LISTENER_A",
				"A_DG",
				"LISTENER_A_DG",
			]
		Returns None if an error
		'''
		if not re.fullmatch(r"[A-Za-z0-9_#$]+", value):
			logging.error(f"SID {value} contains invalid characters")
		parts = value.split("_")
		result = []
		seen = set()
		for length in range(1, len(parts) + 1):
			for start in range(len(parts) - length + 1):
				substring = "_".join(parts[start:start + length])
				if substring not in seen:
					seen.add(substring)
					result.append(substring)
		return result

	def loadSidsFromListenerAlias(self):
		'''
		Append ALIAS from listener into the SID list to try ALIAS like SID
		'''
		logging.info('Put listener ALIAS into the SID list to try ALIAS like SID')
		tnscmd = Tnscmd(self.args)
		tnscmd.getInformation()
		aliasRawList = tnscmd.getAlias()
		if aliasRawList != None and len(aliasRawList)>0:
			sidsPossibleList = self._underscoreSIDSubstrings(aliasRawList[0])
			logging.info(f"These SIDs extracted from ALIAS will be tested too: {sidsPossibleList}")
			if sidsPossibleList != None:
				self.sids += sidsPossibleList

def runSIDGuesserModule(args):
	'''
	Run the SIDGuesser module
	'''
	args['print'].title("Searching valid SIDs")
	sIDGuesser = SIDGuesser(args,args['sids-file'],timeSleep=args['timeSleep'])
	if args['no-alias-like-sid'] == False : sIDGuesser.loadSidsFromListenerAlias()
	sIDGuesser.searchKnownSIDs()
	for aSIDSize in range(args['sids-min-size'], args['sids-max-size']+1):
		sIDGuesser.bruteforceSIDs(size=aSIDSize, charset=args['sid-charset'])
	validSIDsList = sIDGuesser.getValidSIDs()
	if validSIDsList == []:
		args['print'].badNews("No found a valid SID".format(args['server'], args['port']))
	else :
		args['print'].goodNews("SIDs found on the {0}:{1} server: {2}".format(args['server'], args['port'], ','.join(validSIDsList)))
	return validSIDsList



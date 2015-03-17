#!/usr/bin/python
# -*- coding: utf-8 -*

from OracleDatabase import OracleDatabase
import threading, thread
import logging
import Queue
from texttable import Texttable
from Utils import areEquals
import os
from Constants import *
from Utils import getScreenSize

class Http (OracleDatabase):
	'''
	Allow the user to scan ports
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("Http object created")
		OracleDatabase.__init__(self,args)
		self.ERROR_NO_HTTP = "ORA-29263: "
		self.ERROR_PROTOCOL = "ORA-29259: "	
		self.ERROR_NO_OPEN = "ORA-12541: "
		self.ERROR_TIMEOUT = "ORA-12535: "
		self.ERROR_TRANSF_TIMEOUT = "ORA-29276: "
		self.ERROR_UTL_TCP_NETWORK = "ORA-29260: "

	class scanAPort(threading.Thread):

		def __init__(self, utlHttpObject,ip,ports,portStatusQueue,pbar,nb,portsQueue,queueLock): 
			threading.Thread.__init__(self)
			self.utlHttpObject = utlHttpObject
			self.ip = ip
			self.portStatusQueue = portStatusQueue
			self.pbar = pbar
			self.nb = nb
			self.portsQueue = portsQueue
			self.queueLock = queueLock
	 
		def run(self):
			protocol, status, info = None, None, None
			while True:
				if self.portsQueue.empty(): thread.exit()
				try :
					port = self.portsQueue.get(block=False)
				except Exception, e:
					thread.exit()
				url = 'http://{0}:{1}/'.format(self.ip, port)
				logging.debug("Scanning "+url+' ... (response in max 60 secs)')
				try:
					response = self.utlHttpObject.tryToConnect(self.ip, port)
				except Exception,e:
					response = self.utlHttpObject.sendGetRequest(url)
				if isinstance(response,Exception):
					logging.debug('Error returned: {0}'.format(response))
					if self.utlHttpObject.ERROR_NO_OPEN in str(response): protocol, status, info = 'tcp','close',self.utlHttpObject.ERROR_NO_OPEN
					elif self.utlHttpObject.ERROR_TIMEOUT in str(response): protocol, status, info = 'tcp','close',self.utlHttpObject.ERROR_TIMEOUT
					elif self.utlHttpObject.ERROR_UTL_TCP_NETWORK in str(response): protocol, status, info = 'tcp','close',self.utlHttpObject.ERROR_UTL_TCP_NETWORK
					elif self.utlHttpObject.ERROR_NO_HTTP in str(response): protocol, status, info = 'tcp','open',self.utlHttpObject.ERROR_NO_HTTP
					elif self.utlHttpObject.ERROR_PROTOCOL in str(response): protocol, status, info = 'tcp','open',self.utlHttpObject.ERROR_PROTOCOL
					elif self.utlHttpObject.ERROR_TRANSF_TIMEOUT in str(response): protocol, status, info = 'tcp','open',self.utlHttpObject.ERROR_TRANSF_TIMEOUT
					else: protocol, status, info = 'tcp','unknown',None
				else : protocol, status, info = 'tcp/HTTP','open',None
				self.queueLock.acquire()
				if protocol != None : self.portStatusQueue.put([port,protocol,status,info])
				nb = self.nb.get(block=False) + 1
				self.nb.put(nb)
				self.pbar.update(nb)
				self.queueLock.release()
				self.portsQueue.task_done()

	def scanTcpPorts(self,httpObject=None,ip=None,ports=[],nbThread=2):
		'''
		Scan tcp port of the ip system
		'''
		pbar,nb = self.getStandardBarStarted(len(ports)),Queue.Queue(1)
		threads, portStatusQueue, portsQueue = [], Queue.Queue(), Queue.Queue()
		queueLock = threading.Lock()
		nb.put(0)
		for aPort in ports : portsQueue.put(aPort)
		for i in range(nbThread):
			thread = httpObject.scanAPort(httpObject,ip,ports,portStatusQueue,pbar,nb, portsQueue,queueLock)
			threads += [thread]
			thread.start()
		portsQueue.join()
		pbar.finish()		
		portStatus = [item for item in portStatusQueue.queue]
		return sorted(portStatus, key=lambda x: int(x[0]))

	def printScanPortResults(self,results):
		'''
		resultats is a list of list
		print resultat of scan port
		'''
		cleanList = []
		results.insert(0,["PORT","PROTOCOL","STATE",'ERROR'])
		table = Texttable(max_width=getScreenSize()[0])
		table.set_deco(Texttable.HEADER)
		if self.args['verbose']<2 :
			for l in results:
				if areEquals(l[2],'close')==False: cleanList.append(l)
			results = cleanList

		table.add_rows(results)
		self.args['print'].goodNews("Scan report for {0}:\n{1}".format(self.args['scan-ports'][0],table.draw()))

	def parseRequest(self,nameFileRequest=None):
		'''
		Parse le fichier nameFile contenant une requête HTTP et retourne
		une liste permettant ensuite d'envoyer la requête avec httlib par
		exemple.
		Exemple d'utilisation:
			conn = httplib.HTTPConnection("root-me.org")
			conn.request(dataReq['method'],dataReq['url'],dataReq['body'],dataReq['header'])
			page = conn.getresponse().read()
			...
			conn.close()
		'''
		TYPE_REQUEST = ['GET','POST']
		if os.path.isfile(nameFileRequest)==False :
			logging.error("File {0} not exist".format(nameFileRequest))
			return None
		f = open(nameFileRequest)
		dataRequest = {'method':'', 'url':'', 'body':None, 'header':{}}
		for nl, l in enumerate(f):
			if nl==0 :
				try :
					lsplit = l.split(" ")
					if len(lsplit) != 3 : 
						logging.error("{0} not contains 3 parts".format(repr(l)))
						return None
					if lsplit[0] in TYPE_REQUEST : 
						dataRequest['method']=lsplit[0]
						dataRequest['url']=lsplit[1]
						dataRequest['version']=lsplit[2].replace('\n','').replace('\t','')
					else : 
						logging.error("{0} not in {1}".format(lsplit[0],TYPE_REQUEST))
						return None
				except:
					logging.error("Error with the first line {0} of the file \'{1}\'".format(repr(l),nameFileRequest))
					return None
			else : 
				try: 
					lsplit = l.split(": ")
					dataRequest['header'][lsplit[0]]=lsplit[1].replace("\n","")
				except:
					logging.error("Error with the line {0} of the file \'{1}\'".format(repr(l),nameFileRequest))
					return None
		f.close()
		return dataRequest

#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging,struct, socket, re, struct
from Constants import *
from Utils import checkOptionsGivenByTheUser

class Tnscmd():
	'''
	Get information about the oracle database service 
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("Tnscmd object created")
		self.args = args
		self.recvdata = ""
		self.alias = []
		self.version = ""
		self.localIP = ""
		
	def getRecvData(self):
		'''
		return a representation of received data
		'''
		return repr(self.recvdata)

	def getInformation(self,cmd='ping'):
		'''
		Get information about the oracle database service 
		Returns False if an error
		Returns True if it has a response
		'''
		logging.info ("alias list emptied")
		self.recvdata = ""
		command = "(CONNECT_DATA=(COMMAND={0}))".format(cmd)
		commandlen = len(command)
		#logging.info("Sending {0} to {1}:{2} in order to get ALIAS".format(command,self.args['server'],self.args['port']))
		clenH = commandlen >> 8
		clenL = commandlen & 0xff
		# calculate packet length
		packetlen = commandlen + 58;	# "preamble" is 58 bytes
		plenH = packetlen >> 8
		plenL = packetlen & 0xff
		# decimal offset
		# 0:   packetlen_high packetlen_low 
		# 26:  cmdlen_high cmdlen_low
		# 58:  command
		packet = [plenH, plenL, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
		0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
		0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01,
		clenH, clenL, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x34, 0xe6, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00]
		#put the command in packet
		for c in command : packet.append(ord(c))
		sendbuf = ''.join([struct.pack('B', val) for val in packet])
		#logging.debug("connect to this service")
		try: 
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(TIMEOUT_TNS_CMD)
			logging.debug("Connection to {0}:{1}".format(self.args['server'],int(self.args['port'])))
			s.connect((self.args['server'],int(self.args['port'])))
			self.localIP = s.getsockname()[0]
			logging.debug("writing {0} bytes: {1}".format(len(sendbuf),repr(sendbuf)))
			s.sendall(sendbuf)
			logging.debug("reading data")
			# read until socket EOF
			self.recvdata = s.recv(999999)
			s.close()
		except socket.timeout,e:	
			logging.critical("Connection Timeout: The server has not responded to the CONNECT_DATA packet send")
			return False
		except Exception,e:
			logging.critical("Connection Error: {0}".format(e))
			return False
		# 1st 12 bytes have some meaning which so far eludes me
		logging.info("Data received thanks to the '{1}' cmd: {0}".format(repr(self.recvdata),cmd))
		return True

	def getAlias(self):
		'''
		return alias list
		'''
		self.alias = []
		self.getInformation(cmd='ping')
		alias = re.findall(r'(?<=ALIAS=).+?(?=\))', self.recvdata, flags=re.IGNORECASE)
		for anAlias in alias : self.alias.append(anAlias.replace('\n','').replace(' ','').replace('\t',''))
		return self.alias
		
	def getVersion(self):
		'''
		return version from VSNNUM
		'''
		self.version = ""
		self.getInformation(cmd='version')
		vsnnum = re.findall(r'(?<=VSNNUM=).+?(?=\))', self.recvdata, flags=re.IGNORECASE)
		if vsnnum == []:
			return "Unknown"
		else:
			hexVsnnum = str(hex(int(vsnnum[0])))[2:]
			if len(hexVsnnum) == 7:
				hexVersionList = struct.unpack('cc2sc2s',hexVsnnum)
			elif len(hexVsnnum) == 8:
				hexVersionList = struct.unpack('2sc2sc2s',hexVsnnum)
			for v in hexVersionList : self.version += str(int(v,16)) + '.'
			return self.version
		
def runTnsCmdModule(args):
	'''
	run the TNS cmd module
	'''
	if checkOptionsGivenByTheUser(args,["version","status","ping"],checkSID=False,checkAccount=False) == False : return EXIT_MISS_ARGUMENT
	tnscmd = Tnscmd(args)
	if args['ping'] == True:
		args['print'].title("Searching ALIAS on the {0} server, port {1}".format(args['server'],args['port']))
		alias = tnscmd.getAlias()
		args['print'].goodNews("{0} ALIAS received: {1}. You should use this alias (more or less) as Oracle SID.".format(len(alias),alias))
	if args['version'] == True:
		args['print'].title("Searching the version of the Oracle database server ({0}) listening on the port {1}".format(args['server'],args['port']))
		version = tnscmd.getVersion()
		args['print'].goodNews("The remote database version is: '{0}'".format(version))
	if args['status'] == True:
		args['print'].title("Searching the server status of the Oracle database server ({0}) listening on the port {1}".format(args['server'],args['port']))
		tnscmd.getInformation(cmd='status')
		args['print'].goodNews("Data received by the database server: '{0}'".format(tnscmd.getRecvData()))
	


#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging,struct, socket, re
from Constants import *

class Tnscmd ():
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

	def resetAlias (self):
		'''
		reset alias
		'''
		logging.info ("alias list emptied")
		self.alias = []

	def getInformation(self,cmd='ping'):
		'''
		Get information about the oracle database service 
		'''
		self.resetAlias()
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
			logging.debug("Connection to {0}:{1}".format(self.args['server'],int(self.args['port'])))
			s.connect((self.args['server'],int(self.args['port'])))
			logging.debug("writing {0} bytes: {1}".format(len(sendbuf),repr(sendbuf)))
			s.sendall(sendbuf)
			logging.debug("reading data")
			# read until socket EOF
			while 1:
				data = s.recv(1024)
				self.recvdata += data
				if not data: break
			s.close()
		except Exception,e:
			logging.critical("Connection Error: {0}".format(e))
		# 1st 12 bytes have some meaning which so far eludes me
		logging.info('Data received thanks to the {1} cmd: {0}'.format(repr(self.recvdata),cmd))
		self.__getAliasStrg__()

	def __getAliasStrg__(self):
		'''
		load aliasstring from self.recvdata
		'''
		alias = re.findall(r'(?<=ALIAS).+?(?=\))', self.recvdata, flags=re.IGNORECASE)
		for anAlias in alias : self.alias.append(anAlias.replace('\n','').replace(' ','').replace('\t','').replace('=',''))
		#logging.info("Alias found: {0}".format(self.alias))

	def getAlias(self):
		'''
		return alias list
		'''
		self.getInformation()
		return self.alias
		
def runTnsCmdModule(args):
	'''
	run the TNS cmd module
	'''
	if args['ping'] == False :
		logging.critical("You must choose the --ping option")
		return EXIT_MISS_ARGUMENT
	args['print'].title("Searching ALIAS on the {0} server, port {1}".format(args['server'],args['port']))
	tnscmd = Tnscmd(args)
	if args['ping'] == True:
		alias = tnscmd.getAlias()
		args['print'].goodNews("{0} ALIAS received: {1}. You should use this alias (more or less) as Oracle SID.".format(len(alias),alias))
		#print alias
	

	


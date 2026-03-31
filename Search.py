#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging, csv, os, warnings
from openpyxl import Workbook
# Suppress openpyxl warning about sheet names > 31 chars.
# This can happen because openpyxl's internal duplicate handling may append
# a suffix after our own truncation. The file is still valid.
warnings.filterwarnings("ignore", message="Title is more than 31 characters", category=UserWarning, module="openpyxl")
from Constants import *
from Utils import checkOptionsGivenByTheUser, getScreenSize
from texttable import Texttable

class Search (OracleDatabase):
	'''
	Serach in Databases, tables and columns
	'''
	
	REQ_INFO_FROM_COLUMN_NAMES = "SELECT owner, table_name, column_name FROM all_tab_columns WHERE column_name LIKE '{0}'" #{0}==pattern
	REQ_VALUE_IN_COLUMN = 'SELECT "{0}" FROM "{1}"."{2}" WHERE "{0}" is not null and rownum = 1' #{0}==column, {1}==database, {2}==table
	REQ_COUNT_ROWS_IN_TABLE = 'SELECT COUNT(*) AS nb FROM "{0}"."{1}"' #{0}==owner, {1}==table
	REQ_GET_ALL_NO_SYSTEM_TABLES = "SELECT DISTINCT owner, table_name FROM all_tables WHERE owner not in ('SYS','SYSTEM')"
	REQ_GET_COLUMNS_FOR_TABLE = "SELECT column_name, data_type FROM all_tab_columns WHERE table_name='{0}' and owner='{1}'" #{0}==table name, {1}==owner
	DEFAULT_VALUE_EMPTY_COLUMN = "(Empty Column)"
	DEFAULT_VALUE_UNKNOWN = "(Unknown)"
	EXEMPLE_VALUE_LEN_MAX = 40
	TRUNCATED_MESSAGE_EXEMPLE = '(Truncated...)'
	
	def __init__(self,args):
		'''
		Constructor
		'''
		logging.debug("Search object created")
		OracleDatabase.__init__(self,args)
		self.__usedSheetNames__ = {}

	def __getUniqueSheetName__(self, name):
		'''
		Returns a unique Excel sheet name, truncated to 31 characters max.
		If the truncated name already exists, appends _2, _3, etc.
		Each returned name is tracked to avoid duplicates.
		'''
		if len(name) > 31:
			name = name[:31]
		if name not in self.__usedSheetNames__:
			self.__usedSheetNames__[name] = 1
			return name
		self.__usedSheetNames__[name] += 1
		suffix = '_{0}'.format(self.__usedSheetNames__[name])
		uniqueName = name[:31 - len(suffix)] + suffix
		# Track the new name too, in case it also collides later
		self.__usedSheetNames__[uniqueName] = 1
		return uniqueName

	def searchInColumns(self, sqlPattern, showEmptyColumns, withoutExample=False):
		'''
		Search sqlpattern in all columns names
		returns a list which contains dicos ex: [{'columnName': 'passwd', 'tableName':'users', 'database':'mysite'}{'columnName': 'password', 'tableName':'users', 'database':'mysitetemp'}]
		'''
		logging.info("Searching pattern '{0}' in column names".format(sqlPattern.upper()))
		results = self.__execQuery__(query=self.REQ_INFO_FROM_COLUMN_NAMES.format(sqlPattern.upper()), ld=['owner', 'table_name', 'column_name'])
		if isinstance(results, Exception):
			logging.error("Impossible to continue in searchInColumns(): {0}".format(results))
			return []
		table = self.getInfoIntable(results, ["owner","table_name","column_name", "example", "nb_rows"], showEmptyColumns=showEmptyColumns, withoutExample=withoutExample)
		return table
		
	def searchPwdKeyworkInColumnNames(self, showEmptyColumns, withoutExample=False):
		'''
		Search sqlpattern in all columns names
		returns a list which contains dicos ex: [{'columnName': 'passwd', 'tableName':'users', 'database':'mysite'}{'columnName': 'password', 'tableName':'users', 'database':'mysitetemp'}]
		'''
		tables = ""
		for aPattern in PATTERNS_COLUMNS_WITH_PWDS:
			table = self.searchInColumns(aPattern, showEmptyColumns=showEmptyColumns, withoutExample=withoutExample)
			if self.isEmptyTable(table) == True :
				logging.debug("Nothing to print. Doesn't print the header of the table!")
			else : 
				logging.debug("Some results, saved")
				try :
					tables += "'"+aPattern+"' in column names:\n"+table+"\n\n"
				except UnicodeDecodeError as e:
					print("------->"+e)
		return tables
		
	def getDescOfEachNoSystemTable(self, tableNames=None, dumpFile=None):
		'''
		tableNames: list of table names (optional). Each entry can be 'TABLE' or 'OWNER.TABLE'.
		            If empty or None, all non-system tables are described.
		dumpFile: base filename for output files (without extension).
		          If specified, generates both <dumpFile>.csv and <dumpFile>.xlsx.
		          If None, output is printed as texttable to stdout.
		returns a String for print
		'''
		self.__usedSheetNames__ = {}
		outputString = ""
		csvFileHandle = None
		csvWriter = None
		wb = None
		if dumpFile is not None:
			baseName = os.path.splitext(dumpFile)[0]
			csvPath = baseName + '.csv'
			xlsxPath = baseName + '.xlsx'
			wb = Workbook()
			wb.remove(wb.active)
			try:
				csvFileHandle = open(csvPath, 'w', newline='', encoding='utf-8')
				csvWriter = csv.writer(csvFileHandle)
			except Exception as e:
				logging.error("Impossible to open file '{0}' for writing: {1}".format(csvPath, e))
				return ""
		if tableNames is None or tableNames == []:
			logging.debug("Getting all no system tables accessible with the current user")
			tablesAccessible = self.__execQuery__(query=self.REQ_GET_ALL_NO_SYSTEM_TABLES, ld=['owner', 'table_name'])
			if isinstance(tablesAccessible,Exception):
				logging.warning("Impossible to execute the request '{0}': {1}".format(self.REQ_GET_ALL_NO_SYSTEM_TABLES, tablesAccessible.generateInfoAboutError(self.REQ_GET_ALL_NO_SYSTEM_TABLES)))
				if csvFileHandle is not None:
					csvFileHandle.close()
				return ""
		else:
			tablesAccessible = []
			for name in tableNames:
				name = name.upper()
				if '.' in name:
					owner, tableName = name.split('.', 1)
					query = "SELECT DISTINCT owner, table_name FROM all_tables WHERE owner='{0}' AND table_name='{1}'".format(owner, tableName)
				else:
					query = "SELECT DISTINCT owner, table_name FROM all_tables WHERE table_name='{0}'".format(name)
				results = self.__execQuery__(query=query, ld=['owner', 'table_name'])
				if isinstance(results, Exception):
					logging.warning("Impossible to execute the request '{0}': {1}".format(query, results.generateInfoAboutError(query)))
				elif results == []:
					logging.warning("Table '{0}' not found or not accessible".format(name))
				else:
					tablesAccessible.extend(results)
		nbTables = len(tablesAccessible)
		colNb = nbTables
		if colNb>0 :
			pbar,currentColNum = self.getStandardBarStarted(colNb), 0
		for aTable in tablesAccessible:
			if colNb>0:
				currentColNum += 1
				pbar.update(currentColNum)
			request = self.REQ_GET_COLUMNS_FOR_TABLE.format(aTable['table_name'], aTable['owner'])
			columnsAndTypes = self.__execQuery__(query=request, ld=['column_name', 'data_type'])
			if isinstance(columnsAndTypes,Exception):
				logging.warning("Impossible to execute the request '{0}': {1}".format(request, columnsAndTypes.generateInfoAboutError(request)))
				continue
			if dumpFile is not None:
				# Write to CSV
				csvWriter.writerow(['{0}.{1}'.format(aTable['owner'], aTable['table_name'])])
				csvWriter.writerow(['column_name', 'data_type'])
				for aLine in columnsAndTypes:
					csvWriter.writerow([aLine['column_name'], aLine['data_type']])
				csvWriter.writerow([])
				# Write to Excel (one sheet per table)
				sheetName = self.__getUniqueSheetName__('{0}.{1}'.format(aTable['owner'], aTable['table_name']))
				ws = wb.create_sheet(title=sheetName)
				ws.append(['column_name', 'data_type'])
				for aLine in columnsAndTypes:
					ws.append([aLine['column_name'], aLine['data_type']])
			else:
				outputString += "\n[+] {0}.{1} ({2}/{3})\n".format(aTable['owner'], aTable['table_name'], currentColNum, colNb)
				resultsToTable = [('column_name', 'data_type')]
				for aLine in columnsAndTypes:
					resultsToTable.append((aLine['column_name'], aLine['data_type']))
				table = Texttable(max_width=getScreenSize()[1])
				table.set_deco(Texttable.HEADER)
				table.add_rows(resultsToTable)
				outputString += table.draw()
				outputString += '\n'
		if colNb>0 : pbar.finish()
		if dumpFile is not None:
			csvFileHandle.close()
			logging.info("Data written to '{0}'".format(csvPath))
			try:
				wb.save(xlsxPath)
				logging.info("Data written to '{0}'".format(xlsxPath))
			except Exception as e:
				logging.error("Impossible to save Excel file '{0}': {1}".format(xlsxPath, e))
		return outputString

	def __parseDumpArg__(self, arg):
		'''
		Parse a single dump argument string.
		Accepted formats:
		- 'EMPLOYEES'                        -> owner=None, tableName='EMPLOYEES', columns=None
		- 'HR.EMPLOYEES'                     -> owner='HR', tableName='EMPLOYEES', columns=None
		- 'EMPLOYEES:USERNAME,PASSWORD'      -> owner=None, tableName='EMPLOYEES', columns=['USERNAME','PASSWORD']
		- 'HR.EMPLOYEES:USERNAME,PASSWORD'   -> owner='HR', tableName='EMPLOYEES', columns=['USERNAME','PASSWORD']
		Returns a tuple: (owner or None, table_name, list of columns or None)
		'''
		columns = None
		if ':' in arg:
			tablePart, colPart = arg.split(':', 1)
			columns = []
			for c in colPart.split(','):
				columns.append(c.strip().upper())
		else:
			tablePart = arg
		tablePart = tablePart.upper()
		if '.' in tablePart:
			owner, tableName = tablePart.split('.', 1)
		else:
			owner = None
			tableName = tablePart
		return owner, tableName, columns

	def __resolveTable__(self, owner, tableName):
		'''
		Resolve a table name to a list of (owner, table_name) dicts via all_tables.
		If owner is specified, filters by owner and table_name.
		If owner is None, filters by table_name only (all schemas).
		'''
		if owner is not None:
			query = "SELECT DISTINCT owner, table_name FROM all_tables WHERE owner='{0}' AND table_name='{1}'".format(owner, tableName)
		else:
			query = "SELECT DISTINCT owner, table_name FROM all_tables WHERE table_name='{0}'".format(tableName)
		results = self.__execQuery__(query=query, ld=['owner', 'table_name'])
		if isinstance(results, Exception):
			logging.warning("Impossible to resolve table '{0}': {1}".format(tableName, results))
			return []
		if results == []:
			logging.warning("Table '{0}' not found or not accessible".format(tableName))
		return results

	def dumpTables(self, dumpArgs, dumpFile=None):
		'''
		Dump data from one or more tables.
		- dumpArgs: list of strings from the command line, e.g. ['HR.EMPLOYEES', 'USERS:PWD,LOGIN']
		  Each string is parsed by __parseDumpArg__() to extract owner, table name and optional columns.
		- dumpFile: base filename for output files (without extension).
		  If specified, generates both <dumpFile>.csv and <dumpFile>.xlsx.
		  If None, output is printed as texttable to stdout.
		'''
		self.__usedSheetNames__ = {}
		outputString = ""
		csvFileHandle = None
		csvWriter = None
		wb = None
		if dumpFile is not None:
			# Remove extension if user provided one, we add our own
			baseName = os.path.splitext(dumpFile)[0]
			csvPath = baseName + '.csv'
			xlsxPath = baseName + '.xlsx'
			wb = Workbook()
			wb.remove(wb.active)
			try:
				csvFileHandle = open(csvPath, 'w', newline='', encoding='utf-8')
				csvWriter = csv.writer(csvFileHandle)
			except Exception as e:
				logging.error("Impossible to open file '{0}' for writing: {1}".format(csvPath, e))
				return ""
		# First pass: resolve all tables and build a list of (owner, table_name, columns) tasks
		tasks = []
		for arg in dumpArgs:
			owner, tableName, columns = self.__parseDumpArg__(arg)
			resolved = self.__resolveTable__(owner, tableName)
			for aTable in resolved:
				tasks.append((aTable['owner'], aTable['table_name'], columns))
		# Second pass: dump each table with a progress bar
		colNb = len(tasks)
		if colNb > 0:
			pbar, currentColNum = self.getStandardBarStarted(colNb), 0
		for tableOwner, tableTableName, columns in tasks:
			if colNb > 0:
				currentColNum += 1
				pbar.update(currentColNum)
			if columns is not None:
				colParts = []
				for c in columns:
					colParts.append('"{0}"'.format(c))
				colList = ', '.join(colParts)
			else:
				colList = '*'
			query = 'SELECT {0} FROM "{1}"."{2}"'.format(colList, tableOwner, tableTableName)
			logging.info("Dumping {0}.{1} with query: {2}".format(tableOwner, tableTableName, query))
			results = self.__execThisQuery__(query=query, getColumnNames=True, stringOnly=True)
			if isinstance(results, Exception):
				logging.warning("Impossible to dump table '{0}'.'{1}': {2}".format(tableOwner, tableTableName, results))
				continue
			if results == [] or results == [()]:
				logging.info("Table '{0}'.'{1}' is empty or returned no data".format(tableOwner, tableTableName))
				continue
			columnNames = list(results[0])
			rows = results[1:]
			if dumpFile is not None:
				# Write to CSV
				csvWriter.writerow(['{0}.{1}'.format(tableOwner, tableTableName)])
				csvWriter.writerow(columnNames)
				for row in rows:
					csvWriter.writerow(row)
				csvWriter.writerow([])
				# Write to Excel (one sheet per table)
				sheetName = self.__getUniqueSheetName__('{0}.{1}'.format(tableOwner, tableTableName))
				ws = wb.create_sheet(title=sheetName)
				ws.append(columnNames)
				for row in rows:
					ws.append(list(row))
			else:
				outputString += "\n[+] {0}.{1} ({2} rows)\n".format(tableOwner, tableTableName, len(rows))
				resultsToTable = [columnNames]
				for row in rows:
					resultsToTable.append(list(row))
				table = Texttable(max_width=getScreenSize()[1])
				table.set_deco(Texttable.HEADER)
				table.add_rows(resultsToTable)
				outputString += table.draw()
				outputString += '\n'
		if colNb > 0:
			pbar.finish()
		if dumpFile is not None:
			csvFileHandle.close()
			logging.info("Data written to '{0}'".format(csvPath))
			try:
				wb.save(xlsxPath)
				logging.info("Data written to '{0}'".format(xlsxPath))
			except Exception as e:
				logging.error("Impossible to save Excel file '{0}': {1}".format(xlsxPath, e))
		return outputString

	def getInfoIntable(self,listOfDicos, columns, showEmptyColumns, withoutExample=False):
		'''
		columns: list which contains column names for the output
		returns a String for print
		'''
		isStringValueInColumn = False
		resultsToTable = [columns]
		colNb = len(listOfDicos)
		if colNb>0 : pbar,currentColNum = self.getStandardBarStarted(colNb), 0
		for e in listOfDicos :
			isStringValueInColumn = False
			if colNb>0 : currentColNum += 1
			if colNb>0 : pbar.update(currentColNum)
			l = []
			l.append(e['owner'])
			l.append(e['table_name'])
			l.append(e['column_name'])
			if withoutExample == True:
				l.append(self.DEFAULT_VALUE_UNKNOWN)
				nbRows = self.__execQuery__(query=self.REQ_COUNT_ROWS_IN_TABLE.format(e['owner'], e['table_name']), ld=['nb'])
				if isinstance(nbRows, Exception) or nbRows == []:
					l.append(self.DEFAULT_VALUE_UNKNOWN)
				else:
					l.append(str(nbRows[0]['nb']))
				resultsToTable.append(l)
			else:
				logging.debug("Search a not null value in the column '{0}' of the table '{1}'.'{2}' ({3}/{4})".format(e['column_name'], e['owner'], e['table_name'],currentColNum,colNb))
				req_value_in_column = self.REQ_VALUE_IN_COLUMN.format(e['column_name'],e['owner'],e['table_name'])
				aValue = self.__execQuery__(query=req_value_in_column, ld=['value'])
				if isinstance(aValue,Exception):
					logging.warning("Impossible to execute the request '{0}' in column names: {1}".format(req_value_in_column, aValue.generateInfoAboutError(req_value_in_column)))
					l.append(self.DEFAULT_VALUE_UNKNOWN)
				elif aValue == [] : l.append(self.DEFAULT_VALUE_EMPTY_COLUMN)
				else :
					value = aValue[0]['value']
					if type(value) is str: 
						isStringValueInColumn = True
						if len(value) > self.EXEMPLE_VALUE_LEN_MAX:
							value = value[0:self.EXEMPLE_VALUE_LEN_MAX] + ' ' +self.TRUNCATED_MESSAGE_EXEMPLE
						l.append(value)
					else: l.append(self.DEFAULT_VALUE_EMPTY_COLUMN)
				if isStringValueInColumn == True or showEmptyColumns==True:
					nbRows = self.__execQuery__(query=self.REQ_COUNT_ROWS_IN_TABLE.format(e['owner'], e['table_name']), ld=['nb'])
					if isinstance(nbRows, Exception) or nbRows == []:
						l.append(self.DEFAULT_VALUE_UNKNOWN)
					else:
						l.append(str(nbRows[0]['nb']))
					resultsToTable.append(l)
		if colNb>0 : pbar.finish()
		table = Texttable(max_width=getScreenSize()[1])
		table.set_deco(Texttable.HEADER)
		table.add_rows(resultsToTable)
		return table.draw()
		
	def isEmptyTable (self, table):
		"""
		String table
		"""
		if table.count('\n') <= 1 :
			return True
		else : 
			return False

	def __isPLSQLBlock__(self, query):
		"""
		Returns True if the query is a PL/SQL block (BEGIN...END or DECLARE...END).
		"""
		stripped = query.strip().upper()
		return stripped.startswith('BEGIN') or stripped.startswith('DECLARE')

	def startInteractiveSQLShell(self):
		"""
		Start an interactive SQL shell
		Return True when finished
		Supports:
		- SELECT queries (displayed as table)
		- DDL/DML (CREATE, INSERT, UPDATE, DELETE, etc.)
		- PL/SQL blocks (BEGIN...END / DECLARE...END) with DBMS_OUTPUT support
		"""
		print("Ctrl-D to close the SQL shell")
		while True:
			theLine = None
			allLines = ""
			print("SQL> ", end='')
			while theLine != "":
				try:
					theLine = input()
				except EOFError:
					print("\nSQL shell closed")
					return True
				allLines += theLine
			if allLines != "":
				# Strip trailing semicolon which causes cx_Oracle errors on regular SQL
				cleanedQuery = allLines.strip()
				if self.__isPLSQLBlock__(cleanedQuery):
					# PL/SQL block: use __execPLSQLwithDbmsOutput__ to capture DBMS_OUTPUT
					results = self.__execPLSQLwithDbmsOutput__(cleanedQuery, addLineBreak=True)
					if isinstance(results, Exception):
						print(results)
					elif results == "":
						print("PL/SQL block executed successfully (no DBMS_OUTPUT)")
					else:
						print(results)
				else:
					# Regular SQL query
					if cleanedQuery.endswith(';'):
						cleanedQuery = cleanedQuery[:-1]
					results = self.__execQuery__(query=cleanedQuery, getColumnNames=True, stringOnly=True)
					if isinstance(results, Exception):
						print(results)
					elif results == [()]:
						print("Executed successfully")
					else:
						table = Texttable(max_width=getScreenSize()[1])
						table.set_deco(Texttable.HEADER)
						table.add_rows(results)
						print(table.draw())

	def getAllPrivs(self):
		'''
		Get all DBA users
		Use the method of Alexander Kornbrust
		See details here https://www.doag.org/formes/pubfiles/11859287/2019-DB-Alexander_Kornbrust-Best_of_Oracle_Security_2019-Praesentation.pdf
		:return:
		'''
		randomViewName = generateRandomString(length=10)
		REQ_CREATE_VIEW = """
		create or replace view v_all_privs as
			SELECT PRIVILEGE, OBJ_OWNER, OBJ_NAME, USERNAME,COMMON,
				LISTAGG(GRANT_TARGET, ',') WITHIN GROUP (ORDER BY GRANT_TARGET) AS GRANT_SOURCES,
				MAX(ADMIN_OR_GRANT_OPT) AS ADMIN_OR_GRANT_OPT,
				MAX(HIERARCHY_OPT) AS HIERARCHY_OPT
			FROM (
				WITH ALL_ROLES_FOR_USER AS (SELECT DISTINCT CONNECT_BY_ROOT GRANTEE AS GRANTED_USER, GRANTED_ROLE FROM DBA_ROLE_PRIVS CONNECT BY GRANTEE = PRIOR GRANTED_ROLE)
				SELECT PRIVILEGE, OBJ_OWNER, OBJ_NAME, USERNAME, COMMON, REPLACE(GRANT_TARGET, USERNAME, 'Direct to user') AS GRANT_TARGET,ADMIN_OR_GRANT_OPT, HIERARCHY_OPT
				FROM (
					SELECT distinct PRIVILEGE, NULL AS OBJ_OWNER, NULL AS OBJ_NAME, GRANTEE AS USERNAME, COMMON, GRANTEE AS GRANT_TARGET, ADMIN_OPTION AS ADMIN_OR_GRANT_OPT, NULL AS HIERARCHY_OPT
					FROM DBA_SYS_PRIVS
					WHERE GRANTEE IN (SELECT USERNAME FROM DBA_USERS)
					UNION ALL
						SELECT PRIVILEGE, NULL AS OBJ_OWNER, NULL AS OBJ_NAME, ALL_ROLES_FOR_USER.GRANTED_USER AS USERNAME, COMMON, GRANTEE AS GRANT_TARGET, ADMIN_OPTION AS ADMIN_OR_GRANT_OPT, NULL AS HIERARCHY_OPT
						FROM DBA_SYS_PRIVS
						JOIN ALL_ROLES_FOR_USER ON ALL_ROLES_FOR_USER.GRANTED_ROLE = DBA_SYS_PRIVS.GRANTEE
					UNION ALL
						SELECT distinct PRIVILEGE, OWNER AS OBJ_OWNER, TABLE_NAME AS OBJ_NAME, GRANTEE AS USERNAME, COMMON, GRANTEE AS GRANT_TARGET, GRANTABLE, HIERARCHY
						FROM DBA_TAB_PRIVS
						WHERE GRANTEE IN (SELECT USERNAME FROM DBA_USERS)
					UNION ALL
						SELECT distinct PRIVILEGE, OWNER AS OBJ_OWNER, TABLE_NAME AS OBJ_NAME, GRANTEE AS USERNAME, COMMON, ALL_ROLES_FOR_USER.GRANTED_ROLE AS GRANT_TARGET, GRANTABLE, HIERARCHY
						FROM DBA_TAB_PRIVS
						JOIN ALL_ROLES_FOR_USER ON ALL_ROLES_FOR_USER.GRANTED_ROLE = DBA_TAB_PRIVS.GRANTEE
					union all
						SELECT distinct PRIVILEGE, OWNER AS OBJ_OWNER, TABLE_NAME||'.'||COLUMN_NAME AS OBJ_NAME, GRANTEE AS USERNAME, COMMON, ALL_ROLES_FOR_USER.GRANTED_ROLE AS GRANT_TARGET, GRANTABLE, null
						FROM DBA_COL_PRIVS
						JOIN ALL_ROLES_FOR_USER ON ALL_ROLES_FOR_USER.GRANTED_ROLE = DBA_COL_PRIVS.GRANTEE
					UNION ALL
						SELECT distinct PRIVILEGE, OWNER AS OBJ_OWNER, TABLE_NAME||'.'||COLUMN_NAME AS OBJ_NAME, GRANTEE AS USERNAME, COMMON, GRANTEE AS GRANT_TARGET, GRANTABLE, null
						FROM DBA_COL_PRIVS
						WHERE GRANTEE IN (SELECT USERNAME FROM DBA_USERS)
				) ALL_USER_PRIVS
			) DISTINCT_USER_PRIVS
			GROUP BY PRIVILEGE, OBJ_OWNER, OBJ_NAME, USERNAME, COMMON
		""".format(randomViewName)
		REQ_DELETE_VIEW = "DROP VIEW oracle_ocm.{0}".format(randomViewName)

	def getBasicInformation(self, printStdout=True):
		'''
		Get basic information about the instance and database
		:return: Dictionary
		'''
		logging.info("getting basic information about instance and database...")
		DEFINITIONS = ({"REQ":"SELECT systimestamp FROM dual",
						"PARAM":"systimestamp",
						"HELP":"System date"},
					   {"REQ": "SELECT banner FROM V$VERSION",
						"PARAM": "banner",
						"HELP": "Version(s)"},
					   {"REQ": "SELECT sys_context('USERENV', 'SERVER_HOST') FROM dual",
						"PARAM": "SERVER_HOST",
						"HELP": "Instance host name"},
					   {"REQ": "SELECT sys_context('USERENV', 'IP_ADDRESS') FROM dual",
						"PARAM": "IP_ADDRESS",
						"HELP": "IP address"},
					   {"REQ": "SELECT sys_context('USERENV', 'DB_NAME') FROM dual",
						"PARAM": "DB_NAME",
						"HELP": "Name of the database - db_name"},
					   {"REQ": "SELECT sys_context('USERENV', 'DB_UNIQUE_NAME') FROM dual",
						"PARAM": "DB_UNIQUE_NAME",
						"HELP": "Name of the database - db_unique_name"},
					   {"REQ": "SELECT sys_context('USERENV', 'INSTANCE_NAME') FROM dual",
						"PARAM": "INSTANCE_NAME",
						"HELP": "Instance name"},
					   {"REQ": "SELECT sys_context('USERENV', 'SERVICE_NAME') FROM dual",
						"PARAM": "SERVICE_NAME",
						"HELP": "Service Name (session)"},
					   {"REQ": "SELECT sys_context('USERENV', 'HOST') FROM dual",
						"PARAM": "HOST",
						"HELP": "Host machine name (client)"},
					   {"REQ": "SELECT sys_context('USERENV', 'OS_USER') FROM dual",
						"PARAM": "OS_USER",
						"HELP": "Username on client OS"},
					   {"REQ": "SELECT sys_context('USERENV', 'LANGUAGE') FROM dual",
						"PARAM": "LANGUAGE",
						"HELP": "Langage"},
					   {"REQ": "SELECT value FROM V$OPTION WHERE parameter = 'Oracle Database Vault'",
						"PARAM": "VALUE",
						"HELP": "Oracle Database Vault is enabled"},
					   {"REQ": "SELECT value FROM V$OPTION WHERE parameter = 'Java'",
						"PARAM": "VALUE",
						"HELP": "JAVA is enabled"},
					   {"REQ": "SELECT UPPER(VALUE) FROM V$PARAMETER WHERE UPPER(NAME) = 'AUDIT_SYS_OPERATIONS'",
						"PARAM": "VALUE",
						"HELP": "Audit is enabled for SYSDBA or SYSOPER"},
					   {"REQ": "SELECT UPPER(VALUE) FROM V$PARAMETER WHERE UPPER(NAME)='AUDIT_TRAIL'",
						"PARAM": "VALUE",
						"HELP": "Basic audit features level"},
					   {"REQ": "SELECT UPPER(VALUE) FROM V$PARAMETER WHERE UPPER(NAME)='SEC_CASE_SENSITIVE_LOGON'",
						"PARAM": "VALUE",
						"HELP": "Case-sensitivity is required for passwords"},
					   {"REQ": "SELECT UPPER(VALUE) FROM V$PARAMETER WHERE UPPER(NAME)='SEC_MAX_FAILED_LOGIN_ATTEMPTS'",
						"PARAM": "VALUE",
						"HELP": "Maximum failed login attemps (connection)"},
					   {"REQ": "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS'",
						"HELP": "Maximum failed login attemps and after locked (days)",
						"TABLE": True},
					   {"REQ": "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='PASSWORD_LOCK_TIME'",
						"HELP": "Password lock time (days)",
						"TABLE": True},
					   {"REQ": "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='PASSWORD_LIFE_TIME'",
						"HELP": "Password life time (days)",
						"TABLE": True},
					   {"REQ": "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='PASSWORD_REUSE_MAX'",
						"HELP": "Password reuse maximum (days)",
						"TABLE": True},
					   {"REQ": "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='PASSWORD_GRACE_TIME'",
						"HELP": "Password grace time (days)",
						"TABLE": True},
					   {"REQ": "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE RESOURCE_NAME='SESSIONS_PER_USER'",
						"HELP": "Sessions per user",
						"TABLE": True},
					   {"REQ": "SELECT * FROM USER_SYS_PRIVS",
						"HELP": "Current user's privileges (via USER_SYS_PRIVS & no recursion on roles)",
						"TABLE": True},
					   {"REQ": "SELECT * FROM USER_ROLE_PRIVS",
						"HELP": "Current user's roles",
						"TABLE": True},
					   {"REQ": "SELECT DISTINCT owner FROM all_tables",
						"HELP": "Databases",
						"TABLE":True},
					   {"REQ": "SELECT username FROM all_users",
						"HELP": "All visible Users",
						"TABLE": True},
					   {"REQ": "SELECT parameter, value FROM V$OPTION",
						"HELP": "Database options and features",
						"TABLE": True},
					   {"REQ": "SELECT * FROM DBA_REGISTRY",
						"HELP": "Components loaded into the database",
						"TABLE": True},
					   {"REQ": "select * from dba_registry_sqlpatch",
						"HELP": "SQL patches installed (>= 12c)",
						"TABLE": True},
					   {"REQ": "SELECT dbms_qopatch.GET_OPATCH_LIST FROM dual",
						"HELP": "SQL patches installed with DBMS_QOPATCH (>= 12c)",
						"TABLE": True},
					   {"REQ": "select * from sys.registry$history",
						"HELP": "SQL patches installed (== 11g)",
						"TABLE": True},
					   )
		print("\n")
		for aDefinition in DEFINITIONS:
			if 'TABLE' in aDefinition and aDefinition['TABLE'] == True:
				getColumnNames = True
				ld = []
			else:
				getColumnNames = False
				ld = [aDefinition["PARAM"]]
			response = self.__execThisQuery__(query=aDefinition["REQ"],
											  ld=ld,
											  isquery=True,
											  getColumnNames=getColumnNames,
											  stringOnly=False)
			if isinstance(response,Exception) :
				logging.warning('Error with the SQL request {0}: {1}'.format(aDefinition["REQ"], str(response)))
				print("--> {0}: unknown".format(aDefinition["HELP"]))
			else:
				if 'TABLE' in aDefinition and aDefinition['TABLE'] == True:
					print("\n--> {0}:".format(aDefinition["HELP"]))
					table = Texttable(max_width=getScreenSize()[1])
					table.set_deco(Texttable.HEADER)
					table.add_rows(response)
					print(table.draw())
				else:
					for aRespone in response:
						print("--> {0}: {1}".format(aDefinition["HELP"], aRespone[aDefinition["PARAM"]]))

		
	def testAll (self):
		'''
		Test all functions
		'''
		self.args['print'].subtitle("Search in column names ?")
		logging.info('Nothing to do, return True')
		self.args['print'].goodNews("OK")
		return True

def runSearchModule(args):
	'''
	Run the Search module
	'''
	status = True
	if checkOptionsGivenByTheUser(args,["test-module","column-names","pwd-column-names","desc-tables","without-example","sql-shell",'basic-info','dump']) == False : return EXIT_MISS_ARGUMENT
	search = Search(args)
	status = search.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the Search module can be used")
		status = search.testAll()
	if args['basic-info'] == True :
		args['print'].title("Test if the Search module can be used")
		status = search.getBasicInformation(printStdout=True)
	if ('column-names' in args)==True and args['column-names']!=None:
		args['print'].title("Columns which contains the pattern '{0}'".format(args['column-names']))
		table = search.searchInColumns(args['column-names'],showEmptyColumns=args['show-empty-columns'], withoutExample=args['without-example'])
		if search.isEmptyTable(table) == True :
			args['print'].badNews("no result found")
		else :
			args['print'].goodNews(table)
	if args['pwd-column-names']==True:
		args['print'].title("Columns which contains the pattern ~password~ like (multi language)")
		table = search.searchPwdKeyworkInColumnNames(showEmptyColumns=args['show-empty-columns'], withoutExample=args['without-example'])
		if search.isEmptyTable(table) == True :
			args['print'].badNews("no result found")
		else :
			args['print'].goodNews(table)
	if args['desc-tables'] is not None:
		if args['desc-tables'] == []:
			args['print'].title("Descibe each table which is accessible by the current user (without system tables)")
		else:
			args['print'].title("Descibe specified tables: {0}".format(', '.join(args['desc-tables'])))
		table = search.getDescOfEachNoSystemTable(tableNames=args['desc-tables'], dumpFile=args['dump-file'])
		if args['dump-file'] is not None:
			baseName = os.path.splitext(args['dump-file'])[0]
			args['print'].goodNews("Data written to '{0}.csv' and '{1}.xlsx'".format(baseName, baseName))
		else:
			print(table)
	if args['dump'] is not None:
		if args['dump-file'] is not None:
			baseName = os.path.splitext(args['dump-file'])[0]
			args['print'].title("Dumping tables to '{0}.csv' and '{1}.xlsx'".format(baseName, baseName))
		else:
			args['print'].title("Dumping tables: {0}".format(', '.join(args['dump'])))
		output = search.dumpTables(dumpArgs=args['dump'], dumpFile=args['dump-file'])
		if args['dump-file'] is not None:
			baseName = os.path.splitext(args['dump-file'])[0]
			args['print'].goodNews("Data written to '{0}.csv' and '{1}.xlsx'".format(baseName, baseName))
		elif output != "":
			print(output)
		else:
			args['print'].badNews("no data found")
	if args['sql-shell'] == True:
		args['print'].title("Starting an interactive SQL shell")
		search.startInteractiveSQLShell()

#!/usr/bin/python
# -*- coding: utf-8 -*-

from OracleDatabase import OracleDatabase
import logging
from Constants import *
from Utils import checkOptionsGivenByTheUser, getScreenSize
from texttable import Texttable

class Search (OracleDatabase):
	'''
	Serach in Databases, tables and columns
	'''
	
	REQ_INFO_FROM_COLUMN_NAMES = "SELECT owner, table_name, column_name FROM all_tab_columns WHERE column_name LIKE '{0}'" #{0}==pattern
	REQ_VALUE_IN_COLUMN = 'SELECT "{0}" FROM "{1}"."{2}" WHERE "{0}" is not null and rownum = 1' #{0}==column, {1}==database, {2}==table
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

	def searchInColumns(self, sqlPattern, showEmptyColumns, withoutExample=False):
		'''
		Search sqlpattern in all columns names
		returns a list which contains dicos ex: [{'columnName': 'passwd', 'tableName':'users', 'database':'mysite'}{'columnName': 'password', 'tableName':'users', 'database':'mysitetemp'}]
		'''
		logging.info("Searching pattern '{0}' in column names".format(sqlPattern.upper()))
		results = self.__execQuery__(query=self.REQ_INFO_FROM_COLUMN_NAMES.format(sqlPattern.upper()), ld=['owner', 'table_name', 'column_name'])
		table = self.getInfoIntable(results, ["owner","table_name","column_name", "example"], showEmptyColumns=showEmptyColumns, withoutExample=withoutExample)
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
				except UnicodeDecodeError,e:
					print "------->"+e
		return tables
		
	def getDescOfEachNoSystemTable(self):
		'''
		returns a String for print
		'''
		outputString = ""
		logging.debug("Getting all no system tables accessible with the current user")
		tablesAccessible = self.__execQuery__(query=self.REQ_GET_ALL_NO_SYSTEM_TABLES, ld=['owner', 'table_name'])
		if isinstance(tablesAccessible,Exception):
			logging.warning("Impossible to execute the request '{0}': {1}".format(self.REQ_GET_ALL_NO_SYSTEM_TABLES, tablesAccessible.generateInfoAboutError(self.REQ_GET_ALL_NO_SYSTEM_TABLES)))
			return ""
		else:
			nbTables = len(tablesAccessible)
			colNb = nbTables
			if colNb>0 : 
				pbar,currentColNum = self.getStandardBarStarted(colNb), 0
			for aTable in tablesAccessible:
				if colNb>0:
					currentColNum += 1
					pbar.update(currentColNum)
				request = self.REQ_GET_COLUMNS_FOR_TABLE.format(aTabl<e['table_name'], aTable['owner'])
				columnsAndTypes = self.__execQuery__(query=request, ld=['column_name', 'data_type'])
				if isinstance(columnsAndTypes,Exception):
					logging.warning("Impossible to execute the request '{0}': {1}".format(request, columnsAndTypes.generateInfoAboutError(request)))
				outputString += "\n[+] {0}.{1} ({2}/{3})\n".format(aTable['owner'], aTable['table_name'], currentColNum, colNb)
				resultsToTable = [('column_name', 'data_type')]
				for aLine in columnsAndTypes:
					resultsToTable.append((aLine['column_name'], aLine['data_type']))
				table = Texttable(max_width=getScreenSize()[0])
				table.set_deco(Texttable.HEADER)
				table.add_rows(resultsToTable)
				outputString += table.draw()
				outputString += '\n'
			if colNb>0 : pbar.finish()
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
				if isStringValueInColumn == True :
					resultsToTable.append(l)
				elif showEmptyColumns==True :
					resultsToTable.append(l)
		if colNb>0 : pbar.finish()
		table = Texttable(max_width=getScreenSize()[0])
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
	if checkOptionsGivenByTheUser(args,["test-module","column-names","pwd-column-names","desc-tables","without-example"]) == False : return EXIT_MISS_ARGUMENT
	search = Search(args)
	status = search.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the Search module can be used")
		status = search.testAll()
	if args.has_key('column-names')==True and args['column-names']!=None:
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
	if args['desc-tables']==True:
		args['print'].title("Descibe each table which is accessible by the current user (without system tables)")
		table = search.getDescOfEachNoSystemTable()
		print table

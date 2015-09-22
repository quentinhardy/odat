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

	def searchInColumns(self, sqlPattern, showEmptyColumns):
		'''
		Search sqlpattern in all columns names
		returns a list which contains dicos ex: [{'columnName': 'passwd', 'tableName':'users', 'database':'mysite'}{'columnName': 'password', 'tableName':'users', 'database':'mysitetemp'}]
		'''
		logging.info("Searching pattern '{0}' in column names".format(sqlPattern.upper()))
		results = self.__execQuery__(query=self.REQ_INFO_FROM_COLUMN_NAMES.format(sqlPattern.upper()), ld=['owner', 'table_name', 'column_name'])
		table = self.getInfoIntable(results, ["owner","table_name","column_name", "example"], showEmptyColumns=showEmptyColumns)
		return table
		
	def searchPwdKeyworkInColumnNames(self, showEmptyColumns):
		'''
		Search sqlpattern in all columns names
		returns a list which contains dicos ex: [{'columnName': 'passwd', 'tableName':'users', 'database':'mysite'}{'columnName': 'password', 'tableName':'users', 'database':'mysitetemp'}]
		'''
		tables = ""
		for aPattern in PATTERNS_COLUMNS_WITH_PWDS:
			table = self.searchInColumns(aPattern, showEmptyColumns=showEmptyColumns)
			if self.isEmptyTable(table) == True :
				logging.debug("Nothing to print. Doesn't print the header of the table!")
			else : 
				logging.debug("Some results, saved")
				try :
					tables += "'"+aPattern+"' in column names:\n"+table+"\n\n"
				except UnicodeDecodeError,e:
					print "------->"+e
		return tables
		
	def getInfoIntable(self,listOfDicos, columns, showEmptyColumns):
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
	if checkOptionsGivenByTheUser(args,["test-module","column-names","pwd-column-names"]) == False : return EXIT_MISS_ARGUMENT
	search = Search(args)
	status = search.connection(stopIfError=True)
	if args['test-module'] == True :
		args['print'].title("Test if the Search module can be used")
		status = search.testAll()
	if args.has_key('column-names')==True and args['column-names']!=None:
		args['print'].title("Columns which contains the pattern '{0}'".format(args['column-names']))
		table = search.searchInColumns(args['column-names'],showEmptyColumns=args['show-empty-columns'])
		if search.isEmptyTable(table) == True :
			args['print'].badNews("no result found")
		else :
			args['print'].goodNews(table)
	if args['pwd-column-names']==True:
		args['print'].title("Columns which contains the pattern ~password~ like (multi language)")
		table = search.searchPwdKeyworkInColumnNames(showEmptyColumns=args['show-empty-columns'])
		if search.isEmptyTable(table) == True :
                        args['print'].badNews("no result found")
                else :
                        args['print'].goodNews(table)

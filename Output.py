#!/usr/bin/python
# -*- coding: utf-8 -*-

#PYTHON_TERMCOLOR_OK
try:
	from termcolor import colored
	TERMCOLOR_AVAILABLE = True
except ImportError:
	TERMCOLOR_AVAILABLE = False


class Output ():
	'''
	All output except log used this object
	'''
	def __init__(self, args):
		'''
		CONSTRUCTOR
		'''
		self.args = args
		self.noColor = args['no-color']
		self.titlePos = 0
		self.subTitlePos = 0
		self.subSubTitlePos = 0

	def title (self, m):
		'''
		print a title
		'''
		server, port = "", ""
		m = m.encode(encoding='UTF-8',errors='ignore')
		self.titlePos += 1
		self.subTitlePos = 0
		if self.args.has_key('server'): server = self.args['server']
		else: server = "Unknown"
		if self.args.has_key('port'): port = self.args['port']
		else: port = "port"
		formatMesg = '\n[{0}] {1}: {2}'.format(self.titlePos,'({0}:{1})'.format(server,port),m)
		if self.noColor == True or TERMCOLOR_AVAILABLE == False: print formatMesg
		else : print colored(formatMesg, 'white',attrs=['bold'])

	def subtitle (self, m):
		'''
		print a subtitle
		'''
		m = m.encode(encoding='UTF-8',errors='ignore')
		self.subTitlePos += 1
		self.subSubTitlePos += 0
		formatMesg = '[{0}.{1}] {2}'.format(self.titlePos, self.subTitlePos, m)
		if self.noColor == True  or TERMCOLOR_AVAILABLE == False: print formatMesg
		else : print colored(formatMesg, 'white',attrs=['bold']) 

	def subsubtitle (self, m):
		'''
		print a sub-subtitle
		'''
		m = m.encode(encoding='UTF-8',errors='ignore')
		self.subSubTitlePos += 1
		formatMesg = '[{0}.{1}.{2}] {3}'.format(self.titlePos, self.subTitlePos, self.subSubTitlePos, m)
		if self.noColor == True  or TERMCOLOR_AVAILABLE == False: print formatMesg
		else : print colored(formatMesg, 'white',attrs=['bold']) 

	def badNews (self, m):
		'''
		print a stop message
		'''
		m = m.encode(encoding='UTF-8',errors='ignore')
		formatMesg = '[-] {0}'.format(m)
		if self.noColor == True  or TERMCOLOR_AVAILABLE == False: print formatMesg
		else : print colored(formatMesg, 'red',attrs=['bold']) 

	def goodNews(self,m):
		'''
		print good news
		'''
		m = m.encode(encoding='UTF-8',errors='ignore')
		formatMesg = '[+] {0}'.format(m)
		if self.noColor == True  or TERMCOLOR_AVAILABLE == False: print formatMesg
		else : print colored(formatMesg, 'green',attrs=['bold']) 

	def unknownNews(self,m):
		'''
		print unknow news
		'''
		m = m.encode(encoding='UTF-8',errors='ignore')
		formatMesg = '[+] {0}'.format(m)
		if self.noColor == True  or TERMCOLOR_AVAILABLE == False: print formatMesg
		else : print colored(formatMesg, 'yellow',attrs=['bold']) 

	def printOSCmdOutput(self,m):
		'''
		print the output of a OS command
		'''
		print m.encode(encoding='UTF-8',errors='ignore')
		
	def getColoredString(self, string, color, attrs=[]):
		'''
		'''
		if self.noColor == True or TERMCOLOR_AVAILABLE == False: return string
		else : return colored(string, color, attrs=attrs)

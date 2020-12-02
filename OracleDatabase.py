#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging, random, string, cx_Oracle
from Utils import areEquals,checkOracleVersion,getOracleConnection,ErrorSQLRequest
from progressbar import *
from time import sleep
from sys import exit
from Constants import *

class OracleDatabase:
    '''
    '''
    def __init__(self,args):
        '''
        Constructor
        '''
        self.args = args
        self.__generateConnectionString__()
        self.oracleDatabaseversion = ''
        self.remoteOS = ''
        self.TARGET_UNAVAILABLE = ["Connect failed because target host or object does not exist",
                                    "listener could not find available handler with matching protocol stack"]
        self.ERROR_BAD_FOLDER_OR_BAD_SYSTEM_PRIV = "ORA-29283: "
        self.ERROR_FILEOPEN_FAILED = "ORA-22288: "
        self.ERROR_NO_PRIVILEGE = "ORA-24247: "
        self.ERROR_NO_PRIVILEGE_INVALID_ID = "ORA-00904: "
        self.ERROR_NOT_SYSDBA = "ORA-28009: "
        self.ERROR_INSUFF_PRIV_CONN = "ORA-01031: "
        self.ERROR_CONN_IMPOSS = "ORA-12541: "
        self.ERROR_XML_DB_SECU_NOT_INST = "ORA-24248: "
        self.ERROR_UNABLE_TO_ACQUIRE_ENV = "Unable to acquire Oracle environment handle"
        self.ERROR_NOT_CONNECTED = "ORA-03114: "
        self.ERROR_SHARED_MEMORY = "ORA-27101: "
        self.ERROR_ACCOUNT_LOCKED = "ORA-28000: "
        self.encoding = args['encoding']
        self.nencoding = args['encoding']

    def __generateConnectionString__(self):
        '''
        Generate Oracle Database connection string
        '''
        if self.args['sidAsServiceName'] == True:
            self.args['tnsConnectionStringMode'] = True
            logging.debug("TNS Connection string mode enabled and SID is used as a SERVICE NAME in connection string")
            self.args['connectionStr'] = "{0}/{1}@(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(Host={2})(Port={3})))(CONNECT_DATA=(SERVICE_NAME={4})))".format(self.args['user'],
                                                                                                                                                                     self.args['password'],
                                                                                                                                                                     self.args['server'],
                                                                                                                                                                     self.args['port'],
                                                                                                                                                                     self.args['sid'])
        elif self.args['tnsConnectionStringMode'] == True:
            self.args['connectionStr'] = "{0}/{1}@(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(Host={2})(Port={3})))(CONNECT_DATA=(SID={4})))".format(self.args['user'],
                                                                                                                                                            self.args['password'],
                                                                                                                                                            self.args['server'],
                                                                                                                                                            self.args['port'],
                                                                                                                                                            self.args['sid'])
        else:
            self.args['connectionStr'] = "{0}/{1}@{2}:{3}/{4}".format(self.args['user'],
                                                                      self.args['password'],
                                                                      self.args['server'],
                                                                      self.args['port'],
                                                                      self.args['sid'])
        logging.debug('Oracle connection string: {0}'.format(self.args['connectionStr']))
        return self.args['connectionStr']
    
    def connection(self,threaded =True, stopIfError=False, encoding=None, nencoding=None):
        '''
        Connection to the database
        'The threaded argument is expected to be a boolean expression which indicates whether or not Oracle
        should use the mode OCI_THREADED to wrap accesses to connections with a mutex. Doing so in single threaded
        applications imposes a performance penalty of about 10-15% which is why the default is False.'
        If stopIfError == True, stop if connection error

        The 'encoding' parameter affects character data such as VARCHAR2 and CLOB columns ("UTF-8" by default).
        The 'nencoding' parameter affects “National Character” data such as NVARCHAR2 and NCLOB ("UTF-8" by default).
        '''
        if encoding == None:
            encoding = self.encoding
        if nencoding == None:
            nencoding =self.nencoding
        logging.debug("Connection encoding set to {0}/{1}".format(repr(encoding), repr(nencoding)))
        try: 
            if self.args['SYSDBA'] == True :
                logging.debug("Connecting as SYSDBA to the database")
                self.args['dbcon'] = cx_Oracle.connect(self.args['connectionStr'],
                                                       mode=cx_Oracle.SYSDBA,
                                                       threaded=threaded,
                                                       encoding=encoding,
                                                       nencoding=nencoding)
            elif self.args['SYSOPER'] == True : 
                logging.debug("Connecting as SYSOPER to the database")
                self.args['dbcon'] = cx_Oracle.connect(self.args['connectionStr'],
                                                       mode=cx_Oracle.SYSOPER,
                                                       threaded=threaded,
                                                       encoding=encoding,
                                                       nencoding=nencoding)
            else :
                self.args['dbcon'] = cx_Oracle.connect(self.args['connectionStr'],
                                                       threaded=threaded,
                                                       encoding=encoding,
                                                       nencoding=nencoding)
            self.args['dbcon'].autocommit = True
            if self.remoteOS == '' and self.oracleDatabaseversion=='' : self.loadInformationRemoteDatabase() 
            return True
        except Exception as e:
            if self.ERROR_CONN_IMPOSS in str(e) or self.ERROR_UNABLE_TO_ACQUIRE_ENV in str(e):
                logging.critical("Impossible to connect to the remost host")
                exit(EXIT_BAD_CONNECTION)
            elif self.ERROR_NOT_SYSDBA in str(e): 
                logging.info("Connection as SYS should be as SYSDBA or SYSOPER, try to connect as SYSDBA")
                self.args['SYSDBA'] = True
                return self.connection(threaded=threaded, stopIfError=stopIfError)
            elif self.ERROR_INSUFF_PRIV_CONN in str(e):
                logging.info("Insufficient privileges, SYSDBA or SYSOPER disabled")
                self.args['SYSDBA'] = False
                self.args['SYSOPER'] = False
                return self.connection(threaded=threaded, stopIfError=stopIfError)
            elif self.ERROR_SHARED_MEMORY in str(e):
                logging.critical("Error server side ('ORA-27101: shared memory realm does not exist').")
                logging.critical("You should try to use a TNS Connection String instead of a connection sting as 'server:port/instance_name'")
                logging.critical("You have to TRY WITH '-t' option!")
                exit(EXIT_BAD_CONNECTION)
            elif stopIfError == True: 
                logging.critical("Impossible to connect to the remote database: {0}".format(self.cleanError(e)))
                exit(EXIT_BAD_CONNECTION)
            else : return ErrorSQLRequest(e)
        

    def __retryConnect__(self, nbTry=3):
        '''
        Try to re connect when TARGET UNAVAILABLE
        return status
        return None if impossible to connect to the database server
        '''
        timesleep, status = 2, ''
        for tryNum in range(nbTry):
            logging.debug("Re connection {0} to the listener on the {1} server".format(tryNum+1, self.args['server']))
            sleep(timesleep)
            status = self.connection()
            if self.__needRetryConnection__(status) == False:
                logging.debug("Re-connection done !")
                return status
            if tryNum == nbTry-1 :
                logging.warning("Becareful! The remote is now unavailable. {0} SID not tried. Perhaps you are doing a DOS on the listener.".format(self.args['sid']))
            timesleep += 4
            logging.debug("Impossible to re-establish the connection!")
        return None
    
    def __needRetryConnection__ (self, status):
        '''
        Return True if need retry the connection (server unaivalable)
        else return False
        '''
        for aString in self.TARGET_UNAVAILABLE:
            if aString in str(status):
                return True
        return False

    def close(self):
        '''
        Close connection to the database
        '''
        if 'dbcon' in self.args:
            try:
                self.args['dbcon'].close()
            except Exception as e:
                logging.debug("Impossible to close the connection to the database: {0}".format(e))

    def __execThisQuery__(self, query=None, ld=[], isquery=True, getColumnNames=False, stringOnly=False):
        '''
        Create a cursor and execute the SQL request in 'query'.
        Return a list of tuples by default e.g. [(valueA, valueB,),(valueAA,valueBB,), etc]
        If ld != [], load in a dictionary all results according to ld (column names) and return a dictionary e.g.
        [{'column1':'valueA', 'column2':'valueB'}, etc]
        If getColumns is enabled (not by default), returns columns in first results. Incompatible with ld otpion.
        If stringOnly enabled, try to convert all columns as string when required (e.g. datetime) or convert to repr()
        if impossible. Incompatible with ld option.
        '''
        results = []
        if ld!=[] and (getColumnNames==True or stringOnly==True):
            logging.error("INTERNAL BUG: ld option is not compatible with getColumnNames or stringOnly in __execThisQuery__(). Fix that quickly!")
        cursor = self.args['dbcon'].cursor()
        try:
            if self.args['show_sql_requests'] == True: logging.info("SQL request executed: {0}".format(query))
            cursor.execute(query)
        except Exception as e:
            logging.info("Impossible to execute the query {0}: '{1}'".format(repr(query), self.cleanError(e)))
            if self.ERROR_NOT_CONNECTED in str(e):
                status = self.__retryConnect__(nbTry=3)
                if status == None :
                    return ErrorSQLRequest("Disconnected. Impossible to re-establish a connection to the database server !")
                else :
                    return self.__execThisQuery__(query=query,ld=ld,isquery=isquery)
            else :
                return ErrorSQLRequest(e)
        if isquery==True :
            try :
                cursor.arraysize = 256
                results = cursor.fetchall()
            except Exception as e:
                if self.cleanError(e) == "not a query":
                    logging.debug("{0} is not a query, returning [] as result".format(query))
                    return [()]
                else:
                    logging.warning("Impossible to fetch all the rows of the query {0}: `{1}`".format(query, self.cleanError(e)))
                    return ErrorSQLRequest(e)
            if stringOnly == True:
                logging.debug("Converting all columns as string if required...")
                resultsAsString = []
                for aR in results:
                    aResultAsString = []
                    for v in aR:
                        vString = None
                        try:
                            vString = str(v)
                        except Exception:
                            logging.debug("Impossible to convert {0} as string for request {1}".format(repr(aR),repr(query)))
                            vString = repr(v)
                        aResultAsString.append(vString)
                    resultsAsString.append(aResultAsString)
                results = resultsAsString
            if getColumnNames==True:
                logging.debug("Extracting column names and returning them in results...")
                columnNames = [row[0] for row in cursor.description]
                results = [tuple(columnNames)] + results
        else : 
            cursor.close()
            return 0
        cursor.close()
        if ld==[] : return results
        else :
            values = []
            for line in results:
                    dico = {}
                    for i in range(len(line)):
                        dico[ld[i]] = line[i]
                    values.append(dico)
            return values

    def __execPLSQL__(self,request):
        '''
        Execute this PL/SQL request
        '''
        return self.__execThisQuery__(query=request,ld=[],isquery=False)
        
    def __execQuery__(self,query,ld=[],getColumnNames=False,stringOnly=False):
        '''
        Execute the query (not PL/SQL) and parse response
        '''
        return self.__execThisQuery__(query=query, ld=ld, isquery=True,getColumnNames=getColumnNames,stringOnly=stringOnly)

    def __execProc__(self,proc,options=None):
        '''
        Execute the stored procedure
        - proc: procedure name
        - options: callproc parameters (see http://cx-oracle.readthedocs.org/en/latest/cursor.html)
        Return True if no error. Otherwise returns Exception (ErrorSQLRequest)
        '''
        cursor = cx_Oracle.Cursor(self.args['dbcon'])
        try:
            if options == None :
                cursor.callproc(proc)
            else:
                cursor.callproc(proc,options)
        except Exception as e:
            logging.info("Impossible to execute the procedure `{0}`: {1}".format(proc, self.cleanError(e)))
            cursor.close()
            return ErrorSQLRequest(e)
        cursor.close()
        return True

    def __execPLSQLwithDbmsOutput__(self,request,addLineBreak=False):
        '''
        Execute the request containing dbms_output  
        '''
        responsedata = ""
        cursor = cx_Oracle.Cursor(self.args['dbcon'])
        try :       
            cursor.callproc("dbms_output.enable")
            try:
                cursor.execute(request)
            except Exception as e:
                logging.info("Impossible to execute the query `{0}`: {1}".format(request, self.cleanError(e)))
                return ErrorSQLRequest(e)
            else :
                statusVar = cursor.var(cx_Oracle.NUMBER)
                lineVar = cursor.var(cx_Oracle.STRING)
                while True:
                    cursor.callproc("dbms_output.get_line", (lineVar, statusVar))
                    if statusVar.getvalue() != 0:
                        break
                    line = lineVar.getvalue()
                    if line == None : 
                        line = ''
                    responsedata += line
                    if addLineBreak == True : responsedata +='\n'
                cursor.close()
        except Exception as e: 
            logging.info("Error with the request: {0}".format(str(e)))
            return ErrorSQLRequest(e)
        return responsedata

    def __generateRandomString__(self, nb=20):
        '''
        Generate a random string of nb chars
        ''' 
        return ''.join(random.choice(string.ascii_uppercase) for x in range(nb))

    def __loadFile__(self, localFile):
        '''
        Return if it is a text file and return data stored in the localFile file
        If an error, return the error
        '''
        logging.debug("Loading the {0} file".format(localFile))
        data = ''
        try:
            f = open(localFile,'rb')
            data = f.read()
            f.close()
        except Exception as e: 
            logging.warning('Error during the read: {0}'.format(str(e)))
            return e
        return data
        
    def getStandardBarStarted(self, maxvalue):
        """Standard status bar"""
        logging.debug("Creating a standard Bar with number of values = {0}".format(maxvalue))
        return ProgressBar(widgets=['', Percentage(), ' ', Bar(),' ', ETA(), ' ',''], maxval=maxvalue).start()

    def cleanError(self,errorMsg):
        '''
        Replace \n and \t by escape
        '''
        return str(errorMsg).replace('\n',' ').replace('\t',' ')

    def writeFile(self,nameFile, data, mode='w'):
        '''
        Write a new file named nameFile containing data
        Return True if Good, otherwise return False
        '''
        logging.info("Create the {0} file".format(nameFile))
        try:
            f = open(nameFile,mode)
            f.write(data)
            f.close()
        except Exception as e: 
            logging.warning('Error during the writing of the {0} file: {1}'.format(nameFile,self.cleanError(e)))
            return False
        return True
        
    def getDatabasePlatfromName(self):
        """
        Return platform_name string from v$database.
        It is possible the current user has not privileges on table v$database.
        Return "" if an error
        """
        platformName = ""
        REQ = "SELECT platform_name FROM v$database"
        REQ2 = "select dbms_utility.port_string from dual"
        response = self.__execQuery__(query=REQ, ld=['platform_name'])
        if isinstance(response,Exception):
            logging.debug("Impossible to get remote platform name with v$database")
            return self.getDatabasePlatfromNameWithPortString()
        else:
            if len(response)>0 and isinstance(response[0],dict):
                platformName = response[0]['platform_name']
                logging.debug("Remote platform name: {0}".format(platformName))
                return platformName
            else:
                logging.debug("Impossible to get remote platform name with  v$database")
                return platformName

    def getDatabasePlatfromNameWithPortString(self):
        """
        Return platform_name string from port_string.
        Return "" if an error
        """
        platformName = ""
        REQ = "select dbms_utility.port_string from dual"
        response = self.__execQuery__(query=REQ, ld=['platform_name'])
        if isinstance(response,Exception):
            logging.debug("Impossible to get remote platform name with port_string")
            return platformName
        else:
            if len(response)>0 and isinstance(response[0],dict):
                platformName = response[0]['platform_name']
                logging.debug("Remote platform name: {0}".format(platformName))
                return platformName
            else:
                logging.debug("Impossible to get remote platform name with port_string")
                return platformName

    def getOSFromPortString(self):
        """
        Return OS string from dbms_utility.port_string
        All users have access to this information
        The DBMS_UTILITY.port_string function returns the operating 
        system and the TWO TASK PROTOCOL version of the database.
        Return "" if an error
        """
        REQ = "SELECT dbms_utility.port_string FROM dual"
        response = self.__execQuery__(query=REQ, ld=['PORT_STRING'])
        if isinstance(response,Exception):
            return ""
        else:
            if len(response)>0 and isinstance(response[0],dict):
                return response[0]['PORT_STRING']
            else:
                return ""

    def loadInformationRemoteDatabase(self):
        '''
        Get the oracle versions
        '''
        if 'dbcon' not in self.args :
            self.remoteOS = ""
            return False
        logging.debug ("Pickup the remote verion")
        self.oracleDatabaseversion = self.args['dbcon'].version
        logging.debug ("Pickup the remote Operating System")
        self.remoteOS = self.getDatabasePlatfromName()
        if self.remoteOS != "":
            logging.info("OS version from getDatabasePlatfromName(): {0}".format(self.remoteOS))
            return True
        self.remoteOS = self.getOSFromPortString()
        if self.remoteOS != "":
            logging.info("OS version from getOSFromPortString: {0}".format(self.remoteOS))
            return True
        REQ = "select rtrim(substr(replace(banner,'TNS for ',''),1,instr(replace(banner,'TNS for ',''),':')-1)) os from v$version where  banner like 'TNS for %'"
        response = self.__execQuery__(query=REQ,ld=['OS'])
        if isinstance(response,Exception):
            return False
        else :
            if isinstance(response,list) and len(response)>0 and isinstance(response[0],dict):
                self.remoteOS = response[0]['OS']
                logging.info("OS version : {0}".format(self.remoteOS))
                return True
            else:
                return False

    def remoteSystemIsWindows(self):    
        '''
        Return True if Windows
        select * from v$transportable_platform; can be used for get all strings possible
        '''
        if self.remoteOS == "":
            self.loadInformationRemoteDatabase()
            if self.remoteOS == "":
                logging.warning("Impossible to known the remote target OS")
        if "windows" in self.remoteOS.lower() or "win_nt" in self.remoteOS.lower(): return True
        else : return False

    def remoteSystemIsLinux(self):  
        '''
        Return True if Linux
        select * from v$transportable_platform; can be used for get all strings possible
        '''
        if self.remoteOS == "":
            self.loadInformationRemoteDatabase()
            if self.remoteOS == "":
                logging.warning("Impossible to known the remote target OS")
        if "linux" in self.remoteOS.lower() or 'solaris' in self.remoteOS.lower() : return True
        else : return False
        
    def isDBVersion(self, version=None):
        '''
        Return True if remote database version is version given in parameter
        '''
        if version in self.oracleDatabaseversion : return True
        else: return False

    def isDBVersionHigherThan11(self, version=None):
        '''
        Return True if remote database version is 11g or higher
        '''
        if self.isDBVersion('11.') or self.isDBVersion('12.') or self.isDBVersion('18.') or self.isDBVersion('19.'):
            return True
        else:
            return False

    def isDBVersionHigherThan12(self, version=None):
        '''
        Return True if remote database version is 12c or higher
        '''
        if self.isDBVersion('12.') or self.isDBVersion('18.') or self.isDBVersion('19.'):
            return True
        else:
            return False
        
    def hasThisRole(self, role, user=None):
        '''
        Returns True if user has role. Otherwise returns False
        Returns None if error
        If user = None, user = current user
        '''
        if user == None : user = self.args['user']
        self.REQ_HAS_THIS_ROLE = "SELECT username FROM user_role_privs WHERE username='{0}' and granted_role='{1}'".format(user.upper(), role)
        response = self.__execQuery__(query=self.REQ_HAS_THIS_ROLE,ld=['username'])
        if isinstance(response,Exception):
            logging.info("Impossible to know if {0} has the role {1}: {2}".format(user, role, self.cleanError(response)))
            return None
        else:
            if isinstance(response,list):
                if len(response)==0:
                    logging.debug("{0} has not the '{1}' role".format(user, role))
                    return False
                else:
                    logging.debug("{0} has the '{1}' role".format(user, role))
                    return True
            else:
                logging.info("Impossible to know if {0} has the '{1}' role".format(user, role))
                return None
                
    def hasThisPrivilege (self, privilege, user=None):
        '''
        Returns True if user has privilege. Otherwise returns False
        Returns None if error
        If user = None, user = current user
        '''
        if user == None : user = self.args['user']
        self.REQ_HAS_THIS_PRIVILEGE = "SELECT privilege FROM user_sys_privs WHERE privilege ='{0}'".format(privilege)
        response = self.__execQuery__(query=self.REQ_HAS_THIS_PRIVILEGE,ld=['privilege'])
        if isinstance(response,Exception):
            logging.info("Impossible to know if {0} has the '{1}' privilege: {2}".format(user, privilege, self.cleanError(response)))
            return None
        else:
            if isinstance(response,list):
                if len(response)==0:
                    logging.debug("{0} has not the '{1}' privilege".format(user, privilege))
                    return False
                else:
                    logging.debug("{0} has the '{1}' privilege".format(user, privilege))
                    return True
            else:
                logging.info("Impossible to know if {0} has the '{1}' privilege".format(user, privilege))
                return None
                
    def grantPrivilegeOnObjectToUser(self, privilege, objectname, user):
        '''
        Grant the privilege on objectname to user
        Returns True ifprivilege has been granted. Otherwise returns Exception
        If user = None, user = current user
        '''
        if user == None : user = self.args['user']
        REQUEST_GRANT_PRIVILEGE_ON_OBJECT_TO_USER = "GRANT {0} ON {1} TO {2}".format(privilege, objectname, user)
        logging.info("Trying to grant '{0}' privilege on '{1}' to '{2}'".format(privilege, objectname, user))
        status = self.__execPLSQL__(REQUEST_GRANT_PRIVILEGE_ON_OBJECT_TO_USER)
        if isinstance(status, Exception):
            logging.info("Impossible to grant '{0}' privilege on '{1}' to '{2}': '{3}'".format(privilege, objectname, user, self.cleanError(status)))
            return status
        else : 
            logging.debug("'{0}' privilege on '{1}' to '{2}' has been granted".format(privilege, objectname, user))
            return True
            
    def dropStoredProcedure(self, procName, schema=None):
        '''
        returns True if dropped. Otherwise returns False
        '''
        if schema==None : REQUEST_DROP_STORED_PROCEDURE = "DROP PROCEDURE {0}".format(procName)
        else: REQUEST_DROP_STORED_PROCEDURE = "DROP PROCEDURE {1}.{0}".format(procName, schema)
        logging.info("Trying to drop the stored procedure '{0}'".format(procName))
        status = self.__execPLSQL__(REQUEST_DROP_STORED_PROCEDURE)
        if isinstance(status, Exception):
            logging.info("Impossible to drop the stored procedure '{0}': '{1}'".format(procName, self.cleanError(status)))
            return False
        else : 
            logging.debug("The stored procedure '{0}' has bee dropped".format(procName))
            return True
    
    def dropStoredFunction(self, fctName, schema=None):
        '''
        returns True if dropped. Otherwise returns False
        '''
        if schema==None : REQUEST_DROP_STORED_FUNCTION = "DROP FUNCTION {0}".format(fctName)
        else: REQUEST_DROP_STORED_FUNCTION = "DROP FUNCTION {1}.{0}".format(fctName, schema)
        logging.info("Trying to drop the stored function '{0}'".format(fctName))
        status = self.__execPLSQL__(REQUEST_DROP_STORED_FUNCTION)
        if isinstance(status, Exception):
            logging.info("Impossible to drop the stored function '{0}': '{1}'".format(fctName, self.cleanError(status)))
            return False
        else : 
            logging.debug("The stored function '{0}' has bee dropped".format(fctName))
            return True
            
    def dropIndex(self, indexName, schema=None):
        '''
        returns True if dropped. Otherwise returns False
        '''
        indexName = indexName.upper()
        if schema==None : REQUEST_DROP_INDEX = "DROP INDEX {0}".format(indexName)
        else: REQUEST_DROP_INDEX = "DROP INDEX {1}.{0}".format(indexName, schema)
        logging.info("Trying to drop the index named '{0}'".format(indexName))
        status = self.__execPLSQL__(REQUEST_DROP_INDEX)
        if isinstance(status, Exception):
            logging.info("Impossible to drop the index '{0}': '{1}'".format(indexName, self.cleanError(status)))
            return False
        else : 
            logging.debug("The stored function '{0}' has been dropped".format(indexName))
            return True
            
    def dropTrigger(self, triggerName, schema=None):
        '''
        returns True if dropped. Otherwise returns False
        '''
        triggerName = triggerName.upper()
        if schema==None : REQUEST_DROP_TRIGGER = "DROP TRIGGER {0}".format(triggerName)
        else: REQUEST_DROP_TRIGGER = "DROP TRIGGER {1}.{0}".format(triggerName, schema)
        logging.info("Trying to drop the trigger named '{0}'".format(triggerName))
        status = self.__execPLSQL__(REQUEST_DROP_TRIGGER)
        if isinstance(status, Exception):
            logging.info("Impossible to drop the trigger '{0}': '{1}'".format(triggerName, self.cleanError(status)))
            return False
        else : 
            logging.debug("The trigger '{0}' has been dropped".format(triggerName))
            return True






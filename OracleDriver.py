#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
Oracle driver layer based on python-oracledb.

Thin mode (default): pure Python, no Oracle Instant Client required.
Thick mode (--thick): uses Oracle Instant Client, needed for Native Network Encryption,
databases older than 12.1 and accounts with 10G password verifiers only.

In thin mode, listener and network errors are raised as DPY-xxxx errors and some of them
are not Oracle errors at all (e.g. socket.gaierror). ODAT modules check error messages
for ORA-xxxxx codes, so these errors are translated to the equivalent ORA-xxxxx error here.
'''

import logging, re, socket
import oracledb

DRIVER_NAME = "SQL*PLUS"
CONNECT_TIMEOUT = 60

#Thin mode errors which require thick mode
ERROR_NNE_REQUIRED = "DPY-3001"
ERROR_DB_VERSION_NOT_SUPPORTED = "DPY-3010"
ERROR_VERIFIER_NOT_SUPPORTED = "DPY-3015"
THICK_MODE_REQUIRED = {ERROR_NNE_REQUIRED: "Native Network Encryption or data integrity is required by the server",
					   ERROR_DB_VERSION_NOT_SUPPORTED: "database version is older than 12.1",
					   ERROR_VERIFIER_NOT_SUPPORTED: "account uses a 10G password verifier only"}

#Thin mode error code -> equivalent Oracle error code
DPY_TO_ORA = {"DPY-6001": "ORA-12514", #listener does not currently know of service requested
			  "DPY-6003": "ORA-12505", #listener does not currently know of SID given in connect descriptor
			  "DPY-4011": "ORA-03113", #end-of-file on communication channel
			  }

class OracleDriverError(Exception):
	'''
	Thin mode error translated to the equivalent Oracle error.
	str() returns "ORA-xxxxx: <original error message>"
	'''
	def __init__(self, oraCode, original):
		self.oraCode = oraCode
		self.original = original
		Exception.__init__(self, "{0}: {1}".format(oraCode, original))

def initDriver(thick=False, configDir=None, driverName=DRIVER_NAME):
	'''
	Initialize the driver in thin mode (default) or thick mode
	Return True if no error, otherwise False
	'''
	global DRIVER_NAME
	DRIVER_NAME = driverName
	if thick == False:
		logging.info("python-oracledb {0} in thin mode (no Oracle client required)".format(oracledb.__version__))
		return True
	try:
		logging.info("Using this folder as TNS_ADMIN env var : {0}".format(configDir))
		oracledb.init_oracle_client(config_dir=configDir, driver_name=driverName, error_url="")
		logging.info("python-oracledb {0} in thick mode, Oracle Client version: {1}".format(oracledb.__version__, oracledb.clientversion()))
		return True
	except Exception as e:
		logging.error("Impossible to initialize thick mode (Oracle Instant Client required): {0}".format(str(e)))
		return False

def isThinMode():
	'''
	Return True if thin mode is used
	'''
	return oracledb.is_thin_mode()

def getErrorCode(e):
	'''
	Return the first ORA-xxxxx, DPY-xxxx or TNS-xxxxx error code of an exception or a string.
	Return None if no error code
	'''
	codes = getErrorCodes(e)
	if codes == []:
		return None
	return codes[0]

def getErrorCodes(e):
	'''
	Return all ORA-xxxxx, DPY-xxxx and TNS-xxxxx error codes of an exception or a string, in order.
	Thin mode wraps errors, e.g. "DPY-6005: cannot connect to database ... DPY-6003: SID ... is not registered"
	'''
	return [m.group(0) for m in re.finditer(r"\b(?:ORA|DPY|TNS)-\d{4,5}\b", str(e))]

def getThickModeRequiredCode(e):
	'''
	Return the thin mode error code meaning that thick mode is required, or None
	'''
	for code in getErrorCodes(e):
		if code in THICK_MODE_REQUIRED:
			return code
	return None

def translateError(e):
	'''
	Translate a thin mode error to the equivalent Oracle error.
	Return an OracleDriverError or the original exception if no translation
	'''
	codes = getErrorCodes(e)
	cause = e.__cause__
	for code in codes:
		if code in DPY_TO_ORA:
			return OracleDriverError(DPY_TO_ORA[code], e)
	#Listener refused connection. (Similar to ORA-xxxxx)
	m = re.search(r"Similar to (ORA-\d{5})", str(e))
	if m != None:
		return OracleDriverError(m.group(1), e)
	code = getErrorCode(e)
	if code == "DPY-6005":
		if type(cause).__module__ == "socks":
			return OracleDriverError("ORA-12541", e) #SOCKS proxy error (proxy down, target refused or unreachable)
		if isinstance(cause, ConnectionRefusedError):
			return OracleDriverError("ORA-12541", e) #TNS:no listener
		if isinstance(cause, socket.gaierror):
			return OracleDriverError("ORA-12545", e) #target host or object does not exist
		if isinstance(cause, (TimeoutError, socket.timeout)):
			return OracleDriverError("ORA-12170", e) #TNS:Connect timeout occurred
		if isinstance(cause, OSError):
			return OracleDriverError("ORA-12543", e) #TNS:destination host unreachable
	if isinstance(e, socket.gaierror):
		#raised directly by thin mode when the host name can not be resolved
		return OracleDriverError("ORA-12545", e)
	return e

def connect(user, password, dsn, mode=None):
	'''
	Connect to the database.
	mode: None, oracledb.AUTH_MODE_SYSDBA or oracledb.AUTH_MODE_SYSOPER
	Return the connection. Raise an exception (translated in thin mode) if an error
	'''
	params = {'user': user, 'password': password, 'dsn': dsn}
	if mode != None:
		params['mode'] = mode
	if isThinMode() == True:
		params['driver_name'] = DRIVER_NAME
		params['tcp_connect_timeout'] = CONNECT_TIMEOUT
	try:
		return oracledb.connect(**params)
	except Exception as e:
		if isThinMode() == False:
			raise
		translated = translateError(e)
		if translated is e:
			raise
		raise translated from e

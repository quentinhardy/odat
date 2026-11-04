#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Check if python-oracledb thin mode can be used against a target (no Oracle client required),
or if thick mode (--thick, Oracle Instant Client) is needed. Optionally test one credential.

Without credentials, a connection is done with a random non-existent username: it can not lock
a real account, but the failed login can be logged by the target.
'''

import argparse, getpass, logging, random, string, sys
import oracledb
from OracleDriver import initDriver, connect, getErrorCodes, getThickModeRequiredCode, THICK_MODE_REQUIRED
from SocksProxy import enableSocksProxy

EXPLANATIONS = {
	"ORA-01017": "invalid username/password",
	"ORA-28000": "the account is locked",
	"ORA-28001": "the password has expired (credentials are valid)",
	"ORA-01045": "credentials are valid but the user lacks CREATE SESSION privilege",
	"ORA-28009": "SYS has to connect with --sysdba or --sysoper",
	"ORA-01031": "insufficient privileges for --sysdba/--sysoper",
	"ORA-12505": "SID not registered with the listener",
	"ORA-12514": "service name not registered with the listener",
	"ORA-12541": "no listener (or SOCKS proxy error)",
	"ORA-12545": "host name can not be resolved",
	"ORA-12170": "connection timeout",
}

def explain(error):
	'''
	Return explanations about the error codes in error
	'''
	explanations = []
	thickCode = getThickModeRequiredCode(error)
	if thickCode != None:
		explanations.append("{0}: thin mode can not be used, use --thick ({1})".format(thickCode, THICK_MODE_REQUIRED[thickCode]))
	for code in getErrorCodes(error):
		if code in EXPLANATIONS:
			explanations.append("{0}: {1}".format(code, EXPLANATIONS[code]))
			break
	return explanations

def getDsn(args, useSid):
	'''
	Return the connect descriptor
	'''
	connectData = "SID={0}".format(args.target) if useSid else "SERVICE_NAME={0}".format(args.target)
	return "(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(Host={0})(Port={1})))(CONNECT_DATA=({2})))".format(args.server, args.port, connectData)

def tryConnection(args, user, password, useSid, mode=None):
	'''
	Try a connection and print the result.
	Return True if connected, otherwise False
	'''
	kind = "SID" if useSid else "service name"
	try:
		conn = connect(user, password, getDsn(args, useSid), mode=mode)
	except Exception as e:
		print("[-] ({0} {1}) {2}".format(kind, args.target, str(e).replace("\n", " ")))
		for anExplanation in explain(e):
			print("    => {0}".format(anExplanation))
		return False
	print("[+] ({0} {1}) connected as {2}".format(kind, args.target, user))
	showSessionInformation(conn)
	conn.close()
	return True

def showSessionInformation(conn):
	'''
	Print information about the current session
	'''
	print("    Database version: {0}".format(conn.version))
	cursor = conn.cursor()
	requests = [("Session user", "SELECT sys_context('userenv','session_user') FROM dual"),
				("Network services", "SELECT network_service_banner FROM v$session_connect_info WHERE sid = sys_context('userenv','sid')"),
				("Roles", "SELECT role FROM session_roles ORDER BY 1"),
				("System privileges", "SELECT privilege FROM session_privs ORDER BY 1")]
	for label, request in requests:
		try:
			values = [str(row[0]) for row in cursor.execute(request)]
			print("    {0}: {1}".format(label, ", ".join(values) if values != [] else "(none)"))
		except oracledb.Error as e:
			print("    {0}: {1}".format(label, str(e).splitlines()[0]))
	cursor.close()

def main():
	parser = argparse.ArgumentParser(description="Check if python-oracledb thin mode can be used against an Oracle target, optionally test one credential")
	parser.add_argument('-s', dest='server', required=True, help='server')
	parser.add_argument('-p', dest='port', type=int, default=1521, help='port (default: %(default)s)')
	parser.add_argument('-d', dest='sid', default=None, help='Oracle System ID (SID)')
	parser.add_argument('-n', dest='serviceName', default=None, help='Oracle Service Name')
	parser.add_argument('-U', dest='user', default=None, help='username to test (without: probe with a random non-existent username)')
	parser.add_argument('-P', dest='password', default=None, help='password (asked if -U is given without -P)')
	parser.add_argument('--sysdba', dest='SYSDBA', action='store_true', default=False, help='connection as SYSDBA')
	parser.add_argument('--sysoper', dest='SYSOPER', action='store_true', default=False, help='connection as SYSOPER')
	parser.add_argument('--socks', dest='socks', default=None, metavar='URL', help='SOCKS proxy, e.g. socks5h://127.0.0.1:1080 (socks5h/socks4a: DNS resolution by the proxy)')
	parser.add_argument('-v', dest='verbose', action='store_true', default=False, help='verbose')
	args = parser.parse_args()
	logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s: %(message)s")
	if (args.sid == None) == (args.serviceName == None):
		parser.error("one of -d (SID) or -n (service name) is required")
	args.target = args.sid if args.sid != None else args.serviceName
	useSid = args.sid != None
	if args.socks != None and enableSocksProxy(args.socks) == False:
		return 1
	initDriver(thick=False)
	if args.user == None:
		user = "".join(random.choice(string.ascii_uppercase) for i in range(15))
		print("[*] Probe {0}:{1} with the non-existent user {2}".format(args.server, args.port, user))
		tryConnection(args, user, "".join(random.choice(string.ascii_uppercase) for i in range(8)), useSid)
		print("[*] ORA-01017 means thin mode can be used (no Native Network Encryption required, database >= 12.1)")
		return 0
	password = args.password if args.password != None else getpass.getpass("Password for {0}: ".format(args.user))
	mode = None
	if args.SYSDBA == True: mode = oracledb.AUTH_MODE_SYSDBA
	elif args.SYSOPER == True: mode = oracledb.AUTH_MODE_SYSOPER
	#One attempt only: each failed login counts for the account lockout
	if tryConnection(args, args.user, password, useSid, mode=mode) == True:
		return 0
	return 2

if __name__ == "__main__":
	sys.exit(main())

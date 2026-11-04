#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
SOCKS proxy support (PySocks required).

python-oracledb thin mode and the TNS listener modules open their TCP connections
with socket.create_connection(), which is replaced here to go through the proxy.
Thick mode (Oracle Instant Client) opens its own sockets and is not covered: use proxychains.
'''

import logging, socket
from urllib.parse import urlparse

DEFAULT_SOCKS_PORT = 1080
REMOTE_DNS = False

def remoteDnsEnabled():
	'''
	Return True if host names have to be resolved by the SOCKS proxy (socks5h:// or socks4a://)
	'''
	return REMOTE_DNS

def enableSocksProxy(url):
	'''
	Route TCP connections through the SOCKS proxy given as URL:
	socks5://[user:password@]host[:port], socks5h:// (DNS resolution by the proxy), socks4:// or socks4a://
	Return True if no error, otherwise False
	'''
	global REMOTE_DNS
	try:
		import socks
	except ImportError:
		logging.critical("PySocks is required for SOCKS proxy support: pip3 install pysocks")
		return False
	proxyTypes = {"socks5": socks.SOCKS5, "socks5h": socks.SOCKS5,
				  "socks4": socks.SOCKS4, "socks4a": socks.SOCKS4}
	u = urlparse(url)
	if u.scheme not in proxyTypes or not u.hostname:
		logging.critical("Invalid SOCKS proxy URL: {0} (e.g. socks5h://127.0.0.1:1080)".format(url))
		return False
	REMOTE_DNS = u.scheme in ("socks5h", "socks4a")
	proxyHost, proxyPort = u.hostname, u.port or DEFAULT_SOCKS_PORT

	def createConnection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
		return socks.create_connection(address, timeout, source_address,
									   proxy_type=proxyTypes[u.scheme],
									   proxy_addr=proxyHost, proxy_port=proxyPort,
									   proxy_rdns=REMOTE_DNS,
									   proxy_username=u.username, proxy_password=u.password)
	socket.create_connection = createConnection

	if REMOTE_DNS == True:
		#python-oracledb resolves the target host name before connecting.
		#Return it unresolved, so the proxy does the lookup (e.g. internal host names)
		realGetaddrinfo = socket.getaddrinfo
		def getaddrinfo(host, port, *args, **kwargs):
			if host == proxyHost:
				return realGetaddrinfo(host, port, *args, **kwargs)
			return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, port))]
		socket.getaddrinfo = getaddrinfo
	logging.info("TCP connections go through the SOCKS proxy {0}:{1} ({2}, DNS resolution by the {3})".format(proxyHost, proxyPort, u.scheme, "proxy" if REMOTE_DNS else "local system"))
	return True

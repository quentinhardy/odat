#!/usr/bin/python
# -*- coding: utf-8 -*-

import http.server
import socketserver
import logging

global_served = False
global_content_file = b""

class HandlerHTTP(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        # Construct a server response.
        global global_content_file
        self.send_response(200)
        self.send_header('Content-Disposition', 'attachment; filename=t123ABCD.txt')
        self.send_header('Content-type','application/x-binary')
        self.end_headers()
        self.wfile.write(global_content_file)
        global global_served
        global_served = True
        return

def serverFileForOneRequest(ip='0.0.0.0', port=8080, content=b"", timeout=10):
    '''
    Serve the "content" on ip:port for one request only, all in memory (no file is written locally).
    content needs to be bytes
    Returns status (True if file has been served. Otherwise False: no served)
    '''
    global global_served
    global global_content_file
    global_served = False
    global_content_file = content
    logging.info("Server listening on port {0}:{1}...".format(ip, port))
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer((ip, port), HandlerHTTP)
    httpd.timeout=timeout
    logging.debug("Timeout for http server set on {0} scds".format(timeout))
    httpd.handle_request()
    httpd.server_close()
    logging.debug("Server closed")
    logging.info("File has been downloaded: {0}".format(global_served))
    return global_served
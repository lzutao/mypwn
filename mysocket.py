#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import socket

__all__ = [
		'myconnect',
		'recvuntil',
		'telnet',
	]

def myconnect(host, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((host, port))
	return sock

def recvall(s):
	data = ''
	buf = s.recv(1024)
	while buf != '':
		data += buf
		buf = s.recv(1024)
	return data

def recvuntil(s, pattern):
	data = ''
	buf = s.recv(1024)
	while buf != '':
		data += buf
		if pattern in data:
			break
		buf = s.recv(1024)
	return data

def telnet(s):
	import telnetlib
	print('Telneting to socket ...')
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()


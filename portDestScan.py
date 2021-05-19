#!/usr/bin/python3

# May 4, 2021 J.A. Waters
# This script is public domain

# Import option parsing, sockets, struct, and regex for character matching
import re, socket, struct
from argparse import ArgumentParser

def ip2int(ipaddr):
	# Use octet range of 0 - 256 to multiply IP into a single integer
	intIP = 0
	for x in range(len(ipaddr)):
		if x == 0:
			intIP = int(ipaddr[x])
		else:
			intIP = intIP * 256 + int(ipaddr[x])
	
	return intIP
	
def int2ip(intIP):
	# By Rikard Bosnjakovic
	return socket.inet_ntoa(struct.pack('!I', intIP))

def numCheck(num, sep=".", type="ip"):
	tNum = num.split(sep)
	nNum = []
	for i, item in enumerate(tNum):
		# Make sure there are only numbers, zeroes if not
		item = item.strip()
		if re.search('[a-zA-Z]', item):
			item = 0
		# For IPs, only 0 - 256 in the octets
		if type == "ip" and (int(item) > 255 or int(item) < 0):
			item = 0
			
		nNum.insert(len(nNum), int(item))

	return nNum

def ipRange(start, end):
	# Split the octets of two IPs in list form, convert to integers, then find the IPs between them
	ipList = []
	startInt = ip2int(start)
	endInt = ip2int(end)

	# Only proceed if the start is less than the end
	if startInt < endInt:
		for x in range(startInt, endInt + 1):
			ipList.insert(len(ipList), int2ip(x))
	else:
		exit("Ensure that the start IP is a lower value than the end IP.")
	
	return ipList
	
# Entry ----------------------------------------------

helpDesc = "Script to scan a range of ports and addresses for availability."
parser = ArgumentParser(description = helpDesc)

parser.add_argument("-s", "--scan", action = "store_true", default = False, help = "scan known or listed ports to check if they are open; only operating values will show without this option")
parser.add_argument("-d", "--dest", dest = "dest", default = "192.168.0.6", help = "input the IP, a CIDR range, a hyphenated-range, or comma-separated IPs to scan; default 127.0.0.1")
parser.add_argument("-p", "--proto", dest = "proto", default = "53", help = "input a port or group of ports to scan; default 53")
parser.add_argument("-t", "--timeout", dest = "timeout", default = "5", help = "input the timeout before connections close; default of 5")

args = parser.parse_args()

# Do some basic parsing of the options passed from the user
if args.dest is not None:
	ipType = None
	typeCount = 0
	nIPs = []
	
	# Split the octets of the two IP range boundaries, check each octet, then generate the tuple of IPs in that range
	if args.dest.find("-") > -1:
		ipType = "hyphen"
		typeCount = typeCount + 1
	if args.dest.find(",") > -1:
		ipType = "comma"
		typeCount = typeCount + 1
	if args.dest.find("/") > -1:
		ipType = "cidr"
		typeCount = typeCount + 1
	
	if ipType == "hyphen" and typeCount == 1:
		tIPs = args.dest.split('-')
		ipStart = numCheck(tIPs[0])
		ipEnd = numCheck(tIPs[1])

		nIPs = ipRange(ipStart, ipEnd)
	
	# For comma-separated, just split and check each split IP for validity
	if ipType == "comma" and typeCount == 1:
		tIPs = args.dest.split(",")
		for item in tIPs:
			nIPs.insert(len(nIPs), '.'.join([str(elem) for elem in numCheck(item)]))
	
	# For CIDR, find the subnet size by subtracting from 32, then make sure the base network ID matches
	if ipType == "cidr" and typeCount == 1:
		tIPData = args.dest.split("/")
		tCidr = int(tIPData[1])
		tIPInt = ip2int(numCheck(tIPData[0]))
		ipStart = numCheck(int2ip(tIPInt - tIPInt % (2 ** (32 - tCidr))))
		ipEnd = numCheck(int2ip(ip2int(ipStart) + (2 ** (32 - tCidr)) - 1))
		nIPs = ipRange(ipStart, ipEnd)
	
	if typeCount == 0:
		nIPs.insert(len(nIPs), '.'.join([str(elem) for elem in numCheck(args.dest)]))
	
	if typeCount < 2:
		args.dest = nIPs
	else:
		exit("Only use one range type (CIDR, hyphenated, or commas).")

if args.proto is not None:
	splitType = None
	typeCount = 0
	nPorts = []

	args.proto = str(args.proto)
	# Split ports based on the separator found
	if args.proto.find("-") > -1:
		splitType = "hyphen"
		typeCount = typeCount + 1
	if args.proto.find(",") > -1:
		splitType = "comma"
		typeCount = typeCount + 1

	if splitType == "hyphen" and typeCount == 1:
		tPorts = args.proto.split('-')
		pStart = numCheck(tPorts[0], "-", "port")[0]
		pEnd = numCheck(tPorts[1], "-", "port")[0]

		if pStart < pEnd:
			nPorts = []
			for x in range(pStart, pEnd + 1):
				nPorts.insert(len(nPorts), x)
		else:
			exit("Ensure that the start port is a lower value than the end port.")
	
	# For comma-separated, just split and check each split port if valid
	if splitType == "comma" and typeCount == 1:
		#tPorts = args.proto.split(",")
		nPorts = numCheck(args.proto, ",", "port")
	
	if typeCount == 0:
		nPorts.insert(len(nPorts), args.proto)

	if typeCount < 2:
		args.proto = nPorts
	else:
		exit("Only use one range type (CIDR, hyphenated, or commas).")

if args.scan:
	for ip in args.dest:
		for port in args.proto:
			sock = socket.socket()
			sock.settimeout(int(args.timeout))
			try:
				sock.connect((ip, int(port)))
				print("Connected to %s:%s" % (ip, port))
			except Exception as err:
				print("Could not connect to %s:%s - %s" % (ip, port, err))
			finally:
				sock.close()
else:
	print(args)

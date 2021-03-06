#!/usr/bin/python3
# This script is public domain

# Import option parsing, sockets, structs, and regex
import re, socket, struct
from argparse import ArgumentParser

def ip2int(ipaddr):
	# Use octet range of 0 - 256 to multiply IP into a single integer
	intIP = 0
	# loop through each list item (octet)
	for x in range(len(ipaddr)):
		# for the first octet, just set the buffer intIP value
		if x == 0:
			intIP = int(ipaddr[x])
		# for all but the first octet, multiply the current value by 256 and then add the next octet's value
		else:
			intIP = intIP * 256 + int(ipaddr[x])
	
	return intIP
	
def int2ip(intIP):
	# struct.pack uses a ! symbol for network byte order, the I symbol specifies integer data
  	# struct.pack converts the integer IP 3,232,235,521 to b'\xc0\xa8\x00\x01'
	# inet_ntoa pulls that byte IP representation and makes it a decimal-notation string
	return socket.inet_ntoa(struct.pack('!I', intIP))

# A value-type agnostic function to check for numbers in strings and split them into a list for further processing
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
			# add each IP as a new item in the ipList variable
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
parser.add_argument("-c", "--convert", action = "store_true", default = False, help = "just output the IP destination converted to an integer")

args = parser.parse_args()

if args.convert:
	print(ip2int(numCheck(args.dest)))

# Do some basic parsing of the options passed from the user
if args.dest is not None:
	ipType = None
	typeCount = 0
	nIPs = []
	
	# Detect the IP destination type based on a range-specifier: hypens, commas, or CIDR notation
	if args.dest.find("-") > -1:
		ipType = "hyphen"
		typeCount = typeCount + 1
	if args.dest.find(",") > -1:
		ipType = "comma"
		typeCount = typeCount + 1
	if args.dest.find("/") > -1:
		ipType = "cidr"
		typeCount = typeCount + 1
	
	# Split the destination by the range type, hyphen, and then processess to find the list of IPs
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
		
		# For the starting IP, get the network size by subtracting the CIDR from 32, then calculate 2 to the power of that value
		# The start is then found by subtracting the found network size from the user-provided address; making sure to use the host ID
		# Use the int2ip to convert the resulting IP back to a string, then numCheck to convert the string to a list of octets
		# The list of octets is useful as the ipRange function uses the list of octets as its required format
		ipStart = numCheck(int2ip(tIPInt - tIPInt % (2 ** (32 - tCidr))))
		# For the end IP, perform the same steps, but add the network size to the found network start
		ipEnd = numCheck(int2ip(ip2int(ipStart) + (2 ** (32 - tCidr)) - 1))
		
		# Use the range function to find all IPs from start to end
		nIPs = ipRange(ipStart, ipEnd)
	
	if typeCount == 0:
		# If there is no range, just convert the destination into a single-item list
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

#!/usr/bin/python3
# This script is public domain

# Import modules
import ipaddress, re, socket, sys, time

# Entry point
if __name__ == '__main__':
	# Check for arguments, only accept one
	if len(sys.argv) == 2:
	
		# Get the IP string passed from user
		item = sys.argv[1]
		# Remove fore-aft whitespace
		item = item.strip()
		
		# Check if it's an IPv4 address
		reStr = "^((2[0-5][0-5]|1[0-9][0-9]|[1-9][0-9]|[1-9])(\.))((2[0-5][0-5]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.)){2}((2[0-5][0-5]|1[0-9][0-9]|[1-9][0-9]|[0-9])($))"
		ipMatch = re.match(reStr, item)
		if(ipMatch):
			print("%s is an IPv4 Address" % (ipMatch.group()))
		
		# Generate some IPs for testing
		ipTesting = []
		cIP = "192.168.0.1"
		cnt = 0
		while ipaddress.ip_address(cIP) < ipaddress.ip_address("192.168.50.254"):
			cIP = ipaddress.ip_address(cIP) + 1;
			ipTesting.append(str(cIP))
			cnt = cnt + 1
		print("%d IPs generated..." % (cnt))
			
		# Check each one with REGEX and time it
		checkStart = time.time()
		for cIp in ipTesting:
			re.match(reStr, cIp)
		checkEnd = time.time()
		print("Regex testing took %.2f seconds" % (checkEnd - checkStart))
		
		# Check each one with the IP Address module and time it
		checkStart = time.time()
		for cIp in ipTesting:
			try:
				ipaddress.ip_address(cIP)
				isIP = True
			except:
				isIP = False
		checkEnd = time.time()
		print("IP Address Module testing took %.2f seconds" % (checkEnd - checkStart))
		
		# Check each one with splitting and comparisons and time it
		checkStart = time.time()
		for cIp in ipTesting:
			isIp = False
			cOctets = cIp.split(".")
			
			if len(cOctets) == 4:
				for octet in cOctets:
					if int(octet) > 0 and int(octet) < 256:
						isIp = True
				
		checkEnd = time.time()
		print("String splitting testing took %.2f seconds" % (checkEnd - checkStart))
		
		ipv6Test = "fed4:1235::1"
		print("\nThough, the IP Address module can tell that this is an IP: " + ipv6Test)
		try:
			ipaddress.ip_address(ipv6Test)
			print("Yep! Tested!")
		except:
			print("Nope, wrong.")
		
		# Is it a valid DNS entry?
		hIp = ""
		cHost = "ggdsfdsoogle.com"
		try:
			hIp = socket.gethostbyname(cHost)
		except:
			hIp = "not found."
		print("IP for %s is %s" % (cHost, hIp))
		
	else:
		print("\nProvide an IPv4 or hostname to evaluate.\n")

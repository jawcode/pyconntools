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
		reStr = "^((2[0-5][0-5]|1[0-9][0-9]|[1-9][0-9]|[1-9](?=\.)|(?<=\.)[0-9])(\.|$)){4}"
		ipv6regex = "^(([1-2a-fA-F][0-9a-fA-F]{0,3}(?=:)|:(?<=:)[0-9a-fA-F]{1,4}(?=:)){1,5}::((?<=:)[0-9a-fA-F]{1,4})(:|$)([0-9a-fA-F]{1,4}){0,6}|(^[1-9a-fA-F][0-9a-fA-F]{0,3}|:(?<=:)[0-9a-fA-F]{1,4}){8})$"
		ipMatch = re.match(reStr, item)
		if(ipMatch):
			print("%s is an IPv4 Address" % (ipMatch.group()))
		else:
			print("%s is not an IPv4 Address" % (item))
		
		# Generate some IPs for testing
		ipTesting = []
		cIP = "192.168.0.1"
		cnt = 0
		while ipaddress.ip_address(cIP) < ipaddress.ip_address("192.168.50.254"):
			cIP = ipaddress.ip_address(cIP) + 1;
			ipTesting.append(str(cIP))
			cnt = cnt + 1
		print("%d IPs generated..." % (cnt))
		
		ip6Testing = []
		cIP = "fcdf:abcd::0:1"
		cnt = 0
		while ipaddress.ip_address(cIP) < ipaddress.ip_address("fcdf:abcd::0:32fe"):
			cIP = ipaddress.ip_address(cIP) + 1;
			ip6Testing.append(str(cIP))
			cnt = cnt + 1
		print("%d v6 IPs generated..." % (cnt))
		
		# Check each IPv4 address with REGEX and time it
		checkStart = time.time()
		for cIp in ipTesting:
			re.match(reStr, cIp)
		checkEnd = time.time()
		print("Regex testing took %.2f seconds" % (checkEnd - checkStart))
		
		# Check IPv6 with REGEX and time it
		checkStart = time.time()
		for cIp in ip6Testing:
			re.match(ipv6regex, cIp)
		checkEnd = time.time()
		print("Regex IPv6 testing took %.2f seconds" % (checkEnd - checkStart))
		
		# Check each IPv4 address with the IP Address module and time it
		checkStart = time.time()
		for cIp in ipTesting:
			try:
				ipaddress.ip_address(cIP)
				isIP = True
			except:
				isIP = False
		checkEnd = time.time()
		print("IP Address Module testing took %.2f seconds" % (checkEnd - checkStart))
		
		# Check each IPv6 address with the IP Address module and time it
		checkStart = time.time()
		for cIp in ip6Testing:
			try:
				ipaddress.ip_address(cIP)
				isIP = True
			except:
				isIP = False
		checkEnd = time.time()
		print("IP Address Module IPv6 testing took %.2f seconds" % (checkEnd - checkStart))
		
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
		print("\nTest an address with the ipaddress module...")
		try:
			ipaddress.ip_address(ipv6Test)
			print("%s is a valid IPv6 address." % (ipv6Test))
		except:
			print("Nope, wrong.")
		
		if re.match(ipv6regex, ipv6Test):
			print("Regex says %s is a valid IPv6 address too." % (ipv6Test))
		ipv6Test2 = "fed4:1235::34::1"
		if re.match(ipv6regex, ipv6Test2):
			print("But somehow %s is?" % (ipv6Test2))		
		else:
			print("But not? %s" % (ipv6Test2))		
		
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

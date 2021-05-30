#!/usr/bin/python3

# May 23, 2021 J.A. Waters
# Chat over HTTPS; a rough way to share short messages over encrypted channels between systems
# This program is provided under the MIT License

# Imports
import ipaddress, math, multiprocessing, os, requests, socket, ssl, sys, time
from multiprocessing import Pool
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# Allow for parsing args or options, depending on Python versioning
if sys.version_info.major < 3 and sys.version_info.minor < 2:
	from optparse import OptionParser
else:
	from argparse import ArgumentParser

# To suppress mesages about untrusted SSL certificates while using locally-generated keys
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Importing for modules that  aren't included as default
import subprocess, pkg_resources

# Set an object with the required packages
required = {'pyopenssl', 'inputimeout'}
# Get the currently installed packages
installed = {pkg.key for pkg in pkg_resources.working_set}
# Set the date for missing packages
missing = required - installed

# If there are any items missing, install those modules with pip
if missing:
	# Use the system python executable to run pip rather than using the pip module directly imported
	python = sys.executable
	subprocess.check_call([python, '-m', 'pip', 'install', *missing], stdout=subprocess.DEVNULL)
	
# Use the libraries for user interaction
from inputimeout import inputimeout, TimeoutOccurred

# Include OpenSSL for generating SSL keys
from OpenSSL import crypto, SSL

# Make sure buffering doesn't interfere for remote sessions
sys.stdout.reconfigure(line_buffering=True)

# Globals
running = True
serverRun = False
wh = None
output = ""
curOut = "Test Message"
connAttempts = 0

# HTTP class for modifying the basic HTTP server; change the get response and prevent messages from showing up in the console
class HTTPReqs(BaseHTTPRequestHandler):
	stopped = False
	reuseAddress = True

	def do_GET(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.send_header('Connection', 'close')
		self.end_headers()
		
		# Send output from a text file on the local machine			
		textFile = open("./textContent.txt", "r")
		textContent = textFile.read()
		self.wfile.write(textContent.encode())
	
	# Don't log connections
	def log_message(self, format, *args):
		return
	
	# Listen until server terminated
	def serve_forever(self):
		while not self.stopped:
			self.handle_request()
	
	# Create a way to force the server to stop if needed
	def setStop(self):
		self.server_close()
		self.stopped = True
		self.create_dummy_request()
		
# A basic clear screen function, use the different primary commands based on the OS
def cls():
	if os.name == "posix":
		os.system("clear")
	else:
		os.system("cls")

# Allow the program to generate a certificate without pre-staging the files
def cert_gen():
	# Generic nobody details for the cert
	emailAddress="nobody@localhost"
	commonName="nobody"
	countryName="no"
	localityName="nowhere"
	stateOrProvinceName="noplace"
	organizationName="nobusiness"
	organizationUnitName="nounit"
	serialNumber=0
	validityStartInSeconds=0
	validityEndInSeconds=10*365*24*60*60
	# Default file names to be used later
	KEY_FILE = "selfsigned.key"
	CERT_FILE="selfsigned.pem"
	
	# Generate the key
	k = crypto.PKey()
	k.generate_key(crypto.TYPE_RSA, 2048)
	
	# Generate the certificate
	cert = crypto.X509()
	subject = cert.get_subject()
	cert.set_issuer(subject)
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(5*365*24*60*60)
	cert.set_pubkey(k)
	cert.set_serial_number(random.randrange(100000))
	# Make sure version 2 is used, at least; modern browsers have issues with the default
	cert.set_version(2)
	cert.add_extensions([
		crypto.X509Extension(b'subjectAltName', False,
			','.join([
				'DNS:%s' % socket.gethostname(),
				'DNS:*.%s' % socket.gethostname(),
				'DNS:localhost',
				'DNS:*.localhost']).encode()),
		crypto.X509Extension(b"basicConstraints", True, b"CA:false")])

	cert.sign(k, 'SHA256')
		
	with open(CERT_FILE, "wt") as f:
		f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
	with open(KEY_FILE, "wt") as f:
		f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
	
# Function to "send" messages; opens up a file and writes input provided by the user
def sendMessage():
	newOut = input("Input> ")
	prevLines = ""
	lineCount = 0
	
	# Check if the file already exists, if not, just create it instead
	if os.path.exists("./textContent.txt"):
		cFile = open("./textContent.txt", "r")
		prevLines = cFile.read()
		cFile.close()
		lineCount = prevLines.count("\n")
	
	# Get the terminal height to determine how many previous messages to save
	termHeight = globals()["wh"][1]
	if lineCount > math.trunc(termHeight / 5):
		# Count the number of newlines in the current message file
		tLines = prevLines.split("\n")
		# Find out where in the file we should trim off previous messages
		remLen = lineCount - math.trunc(termHeight / 5)
		
		# Loop through the list of lines from the file; only save the lines after the remLen variable
		nLines = ""
		for x in range(remLen, lineCount):
			nLines = nLines + tLines[x] + "\n"
		prevLines = nLines
	
	# Get the current date to prepend on the output string
	curDate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
	# Put the entire output string together with the date / time
	newLines = prevLines + curDate + ": " + newOut + "\n"
	# Open the file and write the full text in one go
	cFile = open("./textContent.txt", "w")
	cFile.write(newLines)
	cFile.close()

# Generate an updatable user interface for the console
def showOutput():
	# Clear the screen and get the terminal height to make a good fit
	cls()
	termHeight = globals()["wh"][1]
	
	outputBuffer = ""
	nOutput = ""
	remoteNum = globals()["output"].count("\n")
	
	# We only want to display as many remote messages as we have room for, truncate the rest
	if remoteNum > math.trunc(termHeight / 3):
		# Follows the same process as for outputting commands, split newlines, count, then rewrite
		tOutput = globals()["output"].split("\n")
		remLen = remoteNum - math.trunc(termHeight / 3)

		for x in range(remLen, remoteNum):
			nOutput = nOutput + tOutput[x] + "\n"
			
		globals()["output"] = nOutput
	
	# Output the locally-stored messages directly from the file
	localLines = ""
	if globals()["serverRun"]:
		if os.path.exists("./textContent.txt"):
			cFile = open("./textContent.txt", "r")
			localLines = cFile.read()
			cFile.close()
	localNum = localLines.count('\n')

	# Use all of the previously-generated variables to output the interface
	outputBuffer = "HTTPS Client"
	# Change the output whether its a client or server
	if globals()["serverRun"]:
		outputBuffer = outputBuffer + " / Server Communication"
	outputBuffer = outputBuffer + ": Type 'q' to quit"
	
	# Don't show local messages if not acting as a server
	if globals()["serverRun"]:
		outputBuffer = outputBuffer + ", 's' to send"
		outputBuffer = outputBuffer + ".\nLocal Messages  ---------------------------------------------------\n\n"
	
		outputBuffer = outputBuffer + localLines
		for x in range(math.trunc(termHeight / 5) - localNum):
			outputBuffer = outputBuffer + "\n"
	
	# We always want to show the remote server's messages, client by default
	outputBuffer = outputBuffer + "\nRemote Messages ---------------------------------------------------\n\n"
	if not globals()["output"] == None:
		outputBuffer = outputBuffer + globals()["output"]

	# Add some extra lines to pad out near the bottom
	for x in range(math.trunc(termHeight / 3) - remoteNum + 4):
		outputBuffer = outputBuffer + "\n"
	
	# If the server's not running, add even more padding
	if not globals()["serverRun"]:
		for x in range(math.trunc(termHeight / 5) + 2):
			outputBuffer = outputBuffer + "\n"
	
	# Output the entire interface in one print statement
	print(outputBuffer, end = "")

# Main function to pull https data as a client
def checkClient(args):
	# Tries to connect, show this if something else errors
	resText = "Attempting to connect..."
	connected = True
	# Use a socket test to see if the remote server is even available
	sock = socket.socket()
	sock.settimeout(2)
	try:
		# If the try statement succeeds, the connected default stands
		sock.connect((args.dest, int(args.port)))
	except Exception as err:
		# If the socket check fails, message this to the user; connection failure and how many times it failed
		globals()["connAttempts"] = globals()["connAttempts"] + 1
		resText = "Could not connect, will keep trying... (Attempt " + str(globals()["connAttempts"]) + ")"
		connected = False
	finally:
		# Tidy up the socket
		sock.close()
	
	# If the connection test succeeds, then actually use a get request to pull data from the remote server
	if connected:
		res = requests.get("https://" + args.dest + ":" + str(args.port), verify=False)
		resText = res.text
	
	# Return whatever was found from the server, or the error messages
	return resText + "\n"

# Main function for server actions	
def runServer(args):
	# Test if certificate already exists, if not, generate a new one
	if not os.path.exists("./selfsigned.pem") or not os.path.exists("./selfsigned.key"):
		cert_gen()
	
	# Start listening on the quad-zip IP to allow network to connect
	httpd = HTTPServer(("0.0.0.0", args.port), HTTPReqs)
	# Make sure we set the socket's SSL functions
	httpd.socket = ssl.wrap_socket (httpd.socket, keyfile="./selfsigned.key", certfile='./selfsigned.pem', server_side=True)

	# Keep serving requests until the program is terminated
	httpd.serve_forever()
	
	# Return the object if we ever need to pull data out of the thread
	return httpd
	
# Entry point
if __name__ == '__main__':
	# General parsing for options / arguments and also for providing help details
	helpDesc = "Client/server program to send/receive data over HTTPS"
	if sys.version_info.major < 3 and sys.version_info.minor < 2:
		parser = OptionParser(description = helpDesc)
	else:
		parser = ArgumentParser(description = helpDesc)

	# Allow the user to choose to act only as a client (Default), act as a server, and choose destination IPs and ports
	# The port is also used for the server if it is being used
	parser.add_argument("-c", "--client", action = "store_true", default = True, help = "act as a client; connect to a destination server")
	parser.add_argument("-s", "--server", action = "store_true", default = False, help = "act as a server; listen for incoming HTTPS connections")
	parser.add_argument("-d", "--dest", dest = "dest", default = "127.0.0.1", help = "input a string variable for the destination IP; default 127.0.0.1")
	parser.add_argument("-p", "--port", dest = "port", default = 4203, help = "input a int or string variable for the destination port; default 4203")

	startOpts = parser.parse_args()

	# Do some basic parsing of the options passed from the user
	if startOpts.dest is not None:
		# Check if the destination address is valid
		try:
			ipaddress.ip_address(startOpts.dest)
		except:
			running = False
			exit("Please input a proper destination address.")

	if startOpts.port is not None:
		# Convert the user's port to an integer
		startOpts.port = int(startOpts.port)

	# If operating as a server, create a separate process for listening and just leave that running in the background
	if startOpts.server:
		serverRes = multiprocessing.Process(target = runServer, args = (startOpts, ))
		serverRes.start()
		# Set a variable to check against whether the server is operating
		serverRun = True
		
		# If it doesn't exist, create the text file the server will use to deliver messages for clients; set it with a blank line
		if not os.path.exists("./textContent.txt"):
			cFile = open("./textContent.txt","w")
			cFile.write("")
			cFile.close()
	
	# Clear the screen to prep for the user interface
	cls()
	
	# Set the global terminal size variable for later use
	wh = os.get_terminal_size()
	# If there's a delay, usres will see this for a few seconds
	print("Starting..." + str(wh[0]) + "," + str(wh[1]))

	# Set up a pool to run the client check as a separate process
	# This way, we can get user input and display output without locking the whole screen
	pool = Pool(processes = 3)
	inRes = pool.apply_async(checkClient, (startOpts, ))
	# Variable to track whether the last client request has gone through or not
	lastResp = False
	
	# Main program loop
	while running:
		# Whenever the checkClient process finishes, display the results
		if inRes.ready():
			# Set the global output variable to whatever the client received
			output = inRes.get()
			# Start the async client task again
			inRes = pool.apply_async(checkClient, (startOpts, ))
			# Response happened, make sure this is relayed with the variable
			lastResp = True

		showOutput()
		
		# Delay the loop to reduce flicker
		time.sleep(.5)
		
		if lastResp:
			try:
				# Use the timeout input to wait for 3 seconds for a command, then loop to refresh things
				lastKey = inputimeout(prompt = ">> ", timeout = 3)
			except TimeoutOccurred:
				# Clear the last key, just in case
				lastKey = None
			
			if not lastKey == None:
				# If the user put in a 'q', shut everything down
				if lastKey == "q":
					# Tell the user its closing, probably won't be seen
					print("\n---- Closing ----\n")
					# Close the loop
					running = False
					
					if serverRun:
						# Sometimes the server hangs, let the user know that
						print("Waiting on local server...")
						# Forcibly terminate the server process
						serverRes.terminate()
				# If the server is running, and the user typed an s, get that input
				if lastKey == "s" and serverRun:
					sendMessage()			
			# Clear the last key to make checking a little safer
			lastKey = None
			# Wait until client's next response before prompting for next command
			lastResp = False
	cls()

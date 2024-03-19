#!/usr/bin/env python3
# Created by GramThanos <gramthanos@gmail.com>

import os
import json
import logging
import subprocess
from flask import Flask
from flask import request
from flask_httpauth import HTTPTokenAuth


app = Flask(__name__)
app.logger.setLevel(logging.INFO)
auth = HTTPTokenAuth(scheme='Bearer')
auth_token = os.environ.get('WEB_SECRET_TOKEN', None)


@auth.verify_token
def verify_token(token):
	if auth_token is None or token == auth_token:
		return True


@app.route('/', methods = ['GET'])
def index():
	return jsonResponse({"message": "Docker OpenVPN API"}, 200)


@app.route('/api/ping', methods = ['POST'])
@auth.login_required
def api_ping():

	# curl -X POST -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/ping --insecure

	# Return response
	return jsonResponse({"message": "pong"}, 200)


@app.route('/api/genconfig', methods = ['POST'])
@auth.login_required
def api_genconfig():


	#curl -X POST -H "Content-Type: application/json" -d '{"SERVER_URL": "udp://protons.ddns.net:1101", "ROUTES": "10.13.1.255/16", "SERVER": "10.13.1.255/25", "DISABLE_DEFROUTE": true, "DISABLE_PUSH_BLOCK_DNS": true, "CLIENT_TO_CLIENT": true}' -H 'Authorization: Bearer example_web_secret' https://192.168.2.51:8001/api/genconfig --insecure

	# curl -X POST -H "Content-Type: application/json" -d '{"host": "udp://protons.ddns.net:1194"}' -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/genconfig --insecure
	# curl -X POST -H "Content-Type: application/json" -d '{"host": "udp://protons.ddns.net:1194", "route": "10.10.0.0/16"}' -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/genconfig --insecure
	# curl -X POST -H "Content-Type: application/json" -d '{"host": "udp://protons.ddns.net:1194", "route": "10.10.0.0/16", "disableDefaultRoot": true, "dontPushDNS": true}' -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/genconfig --insecure

	shell_command = ['ovpn_genconfig']

#	# Check paramters e.g. udp://IP_ADDRESS:3000
#	if not ("host" in request.json) or (not (type(request.json['host']) is str)):
#		return jsonResponse({"error": "Bad Request"}, 500)
#	else:
#		shell_command.append('-u')
#		shell_command.append(request.json['host'])
#
#	if ("route" in request.json):
#		if type(request.json['route']) is str:
#			shell_command.append('-r')
#			shell_command.append(request.json['route'])
#		elif type(request.json['route']) is list:
#			request.json['route'] = list(filter(lambda x: (type(x) is str), request.json['route']))
#			if len(request.json['route']) > 0:
#				shell_command.append('-r')
#				for r in request.json['route']:
#					shell_command.append(r)
#
#	if ("dns" in request.json) and (type(request.json['dns']) is str):
#		if type(request.json['dns']) is str:
#			shell_command.append('-n')
#			shell_command.append(request.json['dns'])
#		elif type(request.json['dns']) is list:
#			request.json['dns'] = list(filter(lambda x: (type(x) is str), request.json['dns']))
#			if len(request.json['dns']) > 0:
#				shell_command.append('-n')
#				for n in request.json['dns']:
#					shell_command.append(n)
#
#	if ("disableDefaultRoot" in request.json) and (type(request.json['disableDefaultRoot']) is bool) and request.json['disableDefaultRoot']:
#		shell_command.append('-d')
#
#	if ("dontPushDNS" in request.json) and (type(request.json['dontPushDNS']) is bool) and request.json['dontPushDNS']:
#		shell_command.append('-D')


	# OVP_AUTH: Authenticate  packets with HMAC using the given message digest algorithm (auth).
	if ('a' in request.json):
		shell_command.append('-a')
		shell_command.append(request.json['a'])
	elif ('AUTH' in request.json):
		shell_command.append('-a')
		shell_command.append(request.json['AUTH'])

	# OVPN_EXTRA_SERVER_CONFIG
	if ('e' in request.json):
		shell_command.append('-e')
		shell_command.append(request.json['e'])
	elif ('EXTRA_SERVER_CONFIG' in request.json):
		shell_command.append('-e')
		shell_command.append(request.json['EXTRA_SERVER_CONFIG'])

	# OVPN_EXTRA_CLIENT_CONFIG
	if ('E' in request.json):
		shell_command.append('-E')
		shell_command.append(request.json['E'])
	elif ('EXTRA_CLIENT_CONFIG' in request.json):
		shell_command.append('-E')
		shell_command.append(request.json['EXTRA_CLIENT_CONFIG'])

	# OVPN_CIPHER: A list of allowable TLS ciphers delimited by a colon (cipher).
	if ('C' in request.json):
		shell_command.append('-C')
		shell_command.append(request.json['C'])
	elif ('CIPHER' in request.json):
		shell_command.append('-C')
		shell_command.append(request.json['CIPHER'])

	# OVPN_TLS_CIPHER: Encrypt packets with the given cipher algorithm instead of the default one (tls-cipher).
	if ('T' in request.json):
		shell_command.append('-T')
		shell_command.append(request.json['T'])
	elif ('TLS_CIPHER' in request.json):
		shell_command.append('-T')
		shell_command.append(request.json['TLS_CIPHER'])

	# OVPN_ROUTES
	if ('r' in request.json):
		shell_command.append('-r')
		shell_command.append(request.json['r'])
	elif ('ROUTES' in request.json):
		shell_command.append('-r')
		shell_command.append(request.json['ROUTES'])

	# OVPN_SERVER: SERVER_SUBNET
	if ('s' in request.json):
		shell_command.append('-s')
		shell_command.append(request.json['s'])
	elif ('SERVER' in request.json):
		shell_command.append('-s')
		shell_command.append(request.json['SERVER'])

	# OVPN_DEFROUTE: Disable default route
	if ('d' in request.json):
		shell_command.append('-d')
	elif ('DISABLE_DEFROUTE' in request.json):
		shell_command.append('-d')

	# OVPN_SERVER_URL: SERVER_PUBLIC_URL
	if ('u' in request.json):
		shell_command.append('-u')
		shell_command.append(request.json['u'])
	elif ('SERVER_URL' in request.json):
		shell_command.append('-u')
		shell_command.append(request.json['SERVER_URL'])

	# OVPN_DISABLE_PUSH_BLOCK_DNS: Disable 'push block-outside-dns'
	if ('b' in request.json):
		shell_command.append('-b')
	elif ('DISABLE_PUSH_BLOCK_DNS' in request.json):
		shell_command.append('-b')

	# OVPN_CLIENT_TO_CLIENT: Enable client-to-client option
	if ('c' in request.json):
		shell_command.append('-c')
	elif ('CLIENT_TO_CLIENT' in request.json):
		shell_command.append('-c')

	# OVPN_PUSH: PUSH
	if ('p' in request.json):
		shell_command.append('-p')
		shell_command.append(request.json['p'])
	elif ('PUSH' in request.json):
		shell_command.append('-p')
		shell_command.append(request.json['PUSH'])

	# OVPN_DNS_SERVERS: DNS_SERVER
	if ('n' in request.json):
		shell_command.append('-n')
		shell_command.append(request.json['n'])
	elif ('DNS_SERVERS' in request.json):
		shell_command.append('-n')
		shell_command.append(request.json['DNS_SERVERS'])

	# OVPN_DNS=0: Do not push dns servers
	if ('D' in request.json):
		shell_command.append('-D')
	elif ('DISABLE_DNS' in request.json):
		shell_command.append('-D')

	# OVPN_NAT=1: Configure NAT to access external server network
	if ('N' in request.json):
		shell_command.append('-N')
	elif ('NAT' in request.json):
		shell_command.append('-N')

	# OVPN_KEEPALIVE: Set keepalive. Default: '10 60'
	if ('k' in request.json):
		shell_command.append('-k')
		shell_command.append(request.json['k'])
	elif ('KEEPALIVE' in request.json):
		shell_command.append('-k')
		shell_command.append(request.json['KEEPALIVE'])

	# OVPN_MTU: Set client MTU
	if ('m' in request.json):
		shell_command.append('-m')
		shell_command.append(request.json['m'])
	elif ('MTU' in request.json):
		shell_command.append('-m')
		shell_command.append(request.json['MTU'])

	# OVPN_DEVICE="tap": Use TAP device (instead of TUN device)
	if ('t' in request.json):
		shell_command.append('-t')
	elif ('TAP' in request.json):
		shell_command.append('-t')

	# OVPN_COMP_LZO: Enable comp-lzo compression.
	if ('z' in request.json):
		shell_command.append('-z')
	elif ('COMP_LZO' in request.json):
		shell_command.append('-z')

	# OVPN_OTP_AUTH: Enable two factor authentication using Google Authenticator.
	if ('2' in request.json):
		shell_command.append('-2')
	elif ('OTP_AUTH' in request.json):
		shell_command.append('-2')

	# OVPN_FRAGMENT: FRAGMENT
	if ('f' in request.json):
		shell_command.append('-f')
		shell_command.append(request.json['f'])
	elif ('FRAGMENT' in request.json):
		shell_command.append('-f')
		shell_command.append(request.json['FRAGMENT'])



	print(request.json)
	result = subprocess.run(shell_command, capture_output=True, check=False)
	print(result.stdout.decode('utf-8'))
	print(result.stderr.decode('utf-8'))
	print(result.returncode)

	# Return response
	return jsonResponse({"message": {
		"stdout": result.stdout.decode('utf-8'),
		"stderr": result.stderr.decode('utf-8'),
		"returncode": result.returncode
	}}, 200)


@app.route('/api/initpki', methods = ['POST'])
@auth.login_required
def api_initpki():

	# curl -X POST -H "Content-Type: application/json" -d '{"password": "th1s_Is_4N_3XamPl3_p455", "common_name": "*"}' -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/initpki --insecure
	# curl -X POST -H "Content-Type: application/json" -d '{"password": false, "common_name": "*"}' -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/initpki --insecure

	# Check paramters
	if not ('password' in request.json) or (not (type(request.json['password']) is str) and not (type(request.json['password']) is bool)):
		return jsonResponse({"error": "Bad Request"}, 500)
	if not ('common_name' in request.json) or (not (type(request.json['common_name']) is str)):
		return jsonResponse({"error": "Bad Request"}, 500)

	# Construct input for the script
	shell_input = ""
	shell_command = ['ovpn_initpki']

	if os.path.exists('/etc/openvpn/pki'):
		shell_input += "yes\n"
	if request.json['password']:
		shell_input += f"{request.json['password']}\n{request.json['password']}\n"
	else:
		shell_command.append('nopass')
	shell_input += f"{request.json['common_name']}\n"

	print(shell_input)
	print(shell_command)
	print(request.json)

	# Start process
	try:
		result = subprocess.Popen(shell_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
		result.communicate(shell_input.encode('utf-8'), timeout=2*60)
	except Exception as e:
		return jsonResponse({"error": "Process took too long to respond."}, 500)

	#stdout = result.stdout.read()
	#stderr = result.stderr.read()

	#print(stdout.decode('utf-8'))
	#print(stderr.decode('utf-8'))
	print(result.returncode)

	if result.returncode != 0:
		return jsonResponse({"error": "Failed to initpki."}, 500)

	# Return response
	return jsonResponse({"message": {
		#"stdout": stdout.decode('utf-8'),
		#"stderr": stderr.decode('utf-8'),
		"returncode": result.returncode
	}}, 200)


@app.route('/api/genclient', methods = ['POST'])
@auth.login_required
def api_genclient():

	# curl -X POST -H "Content-Type: application/json" -d '{"client": "thanos"}' -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/genclient --insecure

	# Check paramters
	if not ('client' in request.json) or (not (type(request.json['client']) is str)):
		return jsonResponse({"error": "Bad Request"}, 500)

	print(request.json)
	result = subprocess.run(['easyrsa', 'build-client-full', request.json['client'], 'nopass'], capture_output=True, check=False)
	print(result.stdout.decode('utf-8'))
	print(result.stderr.decode('utf-8'))
	print(result.returncode)

	# Return response
	return jsonResponse({"message": {
		"stdout": result.stdout.decode('utf-8'),
		"stderr": result.stderr.decode('utf-8'),
		"returncode": result.returncode
	}}, 200)


@app.route('/api/getclient', methods = ['POST'])
@auth.login_required
def api_getclient():

	# curl -X POST -H "Content-Type: application/json" -d '{"client": "thanos"}' -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/getclient --insecure

	# Check paramters
	if not ('client' in request.json) or (not (type(request.json['client']) is str)):
		return jsonResponse({"error": "Bad Request"}, 500)

	print(request.json)
	result = subprocess.run(['ovpn_getclient', request.json['client']], capture_output=True, check=False)
	print(result.stdout.decode('utf-8'))
	print(result.stderr.decode('utf-8'))
	print(result.returncode)

	# Return response
	return jsonResponse({"message": {
		"stdout": result.stdout.decode('utf-8'),
		"stderr": result.stderr.decode('utf-8'),
		"returncode": result.returncode
	}}, 200)


def jsonResponse(data, code):
	return app.response_class(
		response=json.dumps(data),
		status=code,
		mimetype='application/json'
	)


if __name__ == "__main__":
	app.run(host="0.0.0.0", port=8000, debug=False, ssl_context='adhoc')

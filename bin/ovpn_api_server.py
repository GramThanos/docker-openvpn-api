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

	# curl -X POST -H "Content-Type: application/json" -d '{"host": "udp://protons.ddns.net:1194"}' -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/genconfig --insecure
	# curl -X POST -H "Content-Type: application/json" -d '{"host": "udp://protons.ddns.net:1194", "route": "10.10.0.0/16"}' -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/genconfig --insecure
	# curl -X POST -H "Content-Type: application/json" -d '{"host": "udp://protons.ddns.net:1194", "route": "10.10.0.0/16", "disableDefaultRoot": true, "dontPushDNS": true}' -H 'Authorization: Bearer example_web_secret' https://0.0.0.0:8080/api/genconfig --insecure

	shell_command = ['ovpn_genconfig']

	# Check paramters e.g. udp://IP_ADDRESS:3000
	if not ("host" in request.json) or (not (type(request.json['host']) is str)):
		return jsonResponse({"error": "Bad Request"}, 500)
	else:
		shell_command.append('-u')
		shell_command.append(request.json['host'])

	if ("route" in request.json):
		if type(request.json['route']) is str:
			shell_command.append('-r')
			shell_command.append(request.json['route'])
		elif type(request.json['route']) is list:
			request.json['route'] = list(filter(lambda x: (type(x) is str), request.json['route']))
			if len(request.json['route']) > 0:
				shell_command.append('-r')
				for r in request.json['route']:
					shell_command.append(r)

	if ("dns" in request.json) and (type(request.json['dns']) is str):
		if type(request.json['dns']) is str:
			shell_command.append('-n')
			shell_command.append(request.json['dns'])
		elif type(request.json['dns']) is list:
			request.json['dns'] = list(filter(lambda x: (type(x) is str), request.json['dns']))
			if len(request.json['dns']) > 0:
				shell_command.append('-n')
				for n in request.json['dns']:
					shell_command.append(n)

	if ("disableDefaultRoot" in request.json) and (type(request.json['disableDefaultRoot']) is bool) and request.json['disableDefaultRoot']:
		shell_command.append('-d')

	if ("dontPushDNS" in request.json) and (type(request.json['dontPushDNS']) is bool) and request.json['dontPushDNS']:
		shell_command.append('-D')
		

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

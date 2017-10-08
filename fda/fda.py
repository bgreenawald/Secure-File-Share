#!/usr/bin/env python3
import os
import sys
#~ import psycopg2
import getpass
import requests
import json
import urllib.request
#~ from Crypto.Protocol.KDF import PBKDF2
#~ from passlib.hash import pbkdf2_sha256
#~ from passlib.utils.pbkdf2 import get_prf
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random

#~ os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SecureFileShare")
#~ from django.contrib.auth import authenticate

NOMODE = 0
HELP = -1
AUTH_FAILURE = -2
ENCRYPT = 1
SETKEY = 2
SETIV = 3
LIST_REPORTS = 4
VIEW_REPORT = 5
DOWNLOAD_REPORT_FILE = 6
LIST_PUBLIC_REPORTS = 7
DECRYPT = 8
HASH = 9
LIST_GROUP_REPORTS = 10
UPLOAD_FDA = 11
DEBUG_CREDENTIALS = 100

LOCAL_URL = "http://127.0.0.1:8000/"
HEROKU_URL = "https://pure-wildwood-22914.herokuapp.com/"
BASE_URL = HEROKU_URL
#BASE_URL = LOCAL_URL

KEYFILE = "key.txt"
IVFILE = "iv.txt"

#~ Credits to
#~ http://stackoverflow.com/questions/20852664/python-pycrypto-encrypt-decrypt-text-files-with-aes
#~ for significant referencing to encrypting a file, though many sources were consulted beforehand.

def pad(message):
	return message + b"\0" * (AES.block_size - (len(message)-1) % AES.block_size-1)

def generate_iv():
	#~ return Random.new().read(AES.block_size)
	return os.urandom(AES.block_size)

def AES_encrypt_file(filename, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	#~ cipher = RSA.importKey(key)
	#~ print(cipher.exportKey())
	out = open(filename + ".enc", "wb")
	f = open(filename, "rb")
	while True:
		chunk = f.read()
		if (len(chunk) == 0):
			break
		chunk = pad(chunk)
		out.write(cipher.encrypt(chunk))
	out.close()
	f.close()

def RSA_encrypt_file(filename, key):#, iv):
	#~ cipher = AES.new(key, AES.MODE_CBC, iv)
	cipher = RSA.importKey(key)
	#~ print(cipher.exportKey())
	f = open(filename, "rb")
	if (filename.rfind('.aes') != -1):
		filename = filename[0:filename.rfind('.aes')]
	out = open(filename + ".enc", "wb")
	while True:
		chunk = f.read()
		if (len(chunk) == 0):
			break
		chunk = pad(chunk)
		out.write(cipher.encrypt(chunk, 0)[0])
	out.close()
	f.close()

def AES_decrypt_file(filename, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	#~ cipher = RSA.importKey(key)
	inp = open(filename, "rb")
	if (filename.find('.enc') != -1):
		filename = filename[0:filename.find('.enc')]
	out = open(filename, "wb")
	while True:
		chunk = inp.read()
		if (len(chunk) == 0):
			break
		out.write(cipher.decrypt(chunk))
	out.close()
	inp.close()

def RSA_decrypt_file(filename, key):#, iv):
	#~ cipher = AES.new(key, AES.MODE_CBC, iv)
	cipher = RSA.importKey(key)
	inp = open(filename, "rb")
	if (filename.find('.enc') != -1):
		filename = filename[0:filename.find('.enc')]
	out = open(filename, "wb")
	while True:
		chunk = inp.read()
		if (len(chunk) == 0):
			break
		out.write(cipher.decrypt(chunk))
	out.close()
	inp.close()

def hash_code(filename):
	f = open(filename,"rb")
	hash = SHA256.new()
	while True:
		chunk = f.read()
		if (len(chunk) == 0):
			break
		hash.update(chunk)
	return hash.hexdigest()

def getkey(filename):
	f = open(filename, "rb")
	key = b""
	while True:
		chunk = f.read(16)
		if (len(chunk) == 0):
			break
		key += chunk
	return key

def setkey():
	f = open(KEYFILE, "wb")
	key = os.urandom(AES.block_size)
	f.write(key)
	f.close()

def getiv():
	f = open(IVFILE, "rb")
	iv = b""
	while True:
		chunk = f.read(16)
		if (len(chunk) == 0):
			break
		iv += chunk
	return iv

def setiv():
	f = open(IVFILE, "wb")
	iv = generate_iv()
	f.write(iv)
	f.close()

def get_credentials(debug = False):
	uname = input("username: ")
	pword = getpass.getpass("password: ")
	req = requests.Session()
	r = req.post(BASE_URL + "fda/auth/", data={"username":uname, "password":pword})
	if (debug):
		print(r.text)
	ret = json.loads(r.text)
	if (ret['loggedin'] == 'true'):
		return req
	return False

def list_group_reports(cred_req):
	r = cred_req.post(BASE_URL + "fda/list-group-reports/")
	#~ print(r.text)
	ret = json.loads(r.text)
	return ret

def list_public_reports():#cred_req):
	r = requests.get(BASE_URL + "fda/list-public-reports/")
	#~ print(r.text)
	ret = json.loads(r.text)
	return ret

def list_reports(cred_req):
	r = cred_req.post(BASE_URL + "fda/list-reports/")
	ret = json.loads(r.text)
	return ret

def get_public_key(username):
	r = requests.get(BASE_URL + "fda/get-public-key/", params={'username':username})
	#print(r.text)
	ret = json.loads(r.text)
	if (ret['is_user']):
		return ret["PUBLIC_KEY"]
	return False

def get_private_key(filename):
	f = open(filename, "rb")
	key = b""
	while True:
		chunk = f.read()
		if (len(chunk) == 0):
			break
		key += chunk
	return key

def view_report(cred_req, report_id):
	r = cred_req.post(BASE_URL + "fda/view-report/", data={'report_id':report_id})
	#~ print(r.text)
	ret = json.loads(r.text)
	return ret

def download_report_file(cred_req, report_id, file_id, filename):
	f = filename.split('/')
	urllib.request.urlretrieve(BASE_URL + "media/" + filename, f[len(f)-1])
	print('downloaded to ' + f[len(f)-1])
	r = cred_req.post(BASE_URL + "fda/get-sha256-sum/", data={'file_id':file_id})
	ret = json.loads(r.text)
	#~ print(r.text)
	print("SHA256: " + ret['sha256sum'])
	if (ret['sha256sum'] == hash_code(f[len(f)-1])):
		print("Hash codes match; download was successful")
	else:
		print("WARNING: Hash codes do NOT match")

if __name__ == "__main__":
	mode = HELP
	report_id = 0
	file_id = 0
	filename = ""
	given_key = b""

	for i in range(1,len(sys.argv)):
		if (sys.argv[i][0] == '-'):
			for j in range(1,len(sys.argv[i])):
				if (sys.argv[i][j] == 'h') :
					mode = HELP
				elif (sys.argv[i][j] == 'e'):
					mode = ENCRYPT
					i += 1
					if (i + 1 <= len(sys.argv)):
						filename = sys.argv[i]
					else:
						print('error: a file must be specified')
						mode = HELP
					break
				elif (sys.argv[i][j] == 'd'):
					mode = DECRYPT
					if (i+3 <= len(sys.argv)):
						filename = sys.argv[i+1]
						given_key = sys.argv[i+2]
					else:
						print('error: a file and a key must be specified')
						mode = HELP
					break
				elif (sys.argv[i][j] == 's'):
					mode = HASH
					if (i+2 <= len(sys.argv)):
						filename = sys.argv[i+1]
					else:
						print('error: a file must be specified')
						mode = HELP
					break
				elif (sys.argv[i][j] == 'k'):
					mode = SETKEY
					#~ given_key = bytes(sys.argv[i+1], 'utf-8')
					break
				elif (sys.argv[i][j] == 'l'):
					if (len(sys.argv[i]) > 2):
						if (sys.argv[i][j+1] == 'g'):
							mode = LIST_GROUP_REPORTS
						elif (sys.argv[i][j+1] == 'p'):
							mode = LIST_PUBLIC_REPORTS
						else:
							print('error: unrecognized switch ' + sys.argv[i][j+1])
							mode = HELP
					else:
						mode = LIST_REPORTS
					break
				elif (sys.argv[i][j] == 'v'):
					if (sys.argv[i][j+1] == 'r'):
						mode = VIEW_REPORT
					elif (sys.argv[i][j+1] == 'd'):
						mode = DOWNLOAD_REPORT_FILE
					i = i + 1
					if (i+1 == len(sys.argv)):
						report_id = sys.argv[i]
					else:
						print('error: a report id must be specified')
						mode = HELP
					break
				elif (sys.argv[i][j] == 'i'):
					mode = SETIV
					break
				elif (sys.argv[i][j] == 'g'):
					j = j + 1
					if (sys.argv[i][j] == 'c'):
						mode = DEBUG_CREDENTIALS
					elif (sys.argv[i][j] == 'u'):
						mode = UPLOAD_FDA
					break

	if (mode == HELP):
		print("usage: " + sys.argv[0] + " <option>")
		print("where option is one of:")
		print()
		print("        -h                          lists this help text")
		print()
		print("        -e <filename>               encrypts a file")
		print("        -d <filename> <privateKey>  decrypts a file")
		print("        -k                          sets the key")
		print("        -i                          sets an IV value")
		print("        -s <filename>               get the SHA256 hash code for a file")
		print()
		print("        -l                          list all reports for the user")
		print("        -lg                         list all group reports for the user")
		print("        -lp                         list all public reports")
		print("        -vr <r_id>                  view the specified report")
		print("        -vd <r_id>                  download a file from the report")
		print()
		#~ print("        -g<option>                  debug with a sub option")
		#~ print("          c                         authentication")
		print("If you reset any keys, affected files cannot be recovered!")
	elif (mode == ENCRYPT):
		#~ request = get_credentials()
		username = input('target user\'s name: ')
		public_key = get_public_key(username)
		the_key = b''
		the_iv = b''
		try:
			the_key = getkey(KEYFILE)
		except:
			setkey()
			the_key  = getkey(KEYFILE)
		try:
			the_iv = getiv()
		except:
			setiv()
			the_iv = getiv()
		if (public_key != False):
			AES_encrypt_file(filename, the_key, the_iv)
			RSA_encrypt_file(KEYFILE, public_key)#, getiv())
			#~ os.remove(filename+'.aes')
			keyfile = open(KEYFILE + '.enc', 'rb')
			aesfile = open(filename + '.enc', 'rb')
			key = keyfile.read(256)
			aes = []
			while True:
				data = aesfile.read(1024)
				if (len(data) == 0):
					break
				aes.append(data)
			keyfile.close()
			aesfile.close()
			f = open(filename + '.enc', 'wb')
			f.write(key)
			for d in aes:
				f.write(d)
			f.close()
			os.remove(KEYFILE + '.enc')
		else:
			mode = AUTH_FAILURE
	elif (mode == DECRYPT):
		#~ decrypt_file(filename, get_private_key(given_key))
		keyname = "temp_"+KEYFILE
		keyfile = open(keyname + '.enc', 'wb')
		aesfile = open(filename + '.aes', 'wb')
		f = open(filename, 'rb')
		keyfile.write(f.read(256))
		keyfile.close()
		while True:
			data = f.read()
			if (len(data) == 0):
				break
			aesfile.write(data)
		aesfile.close()
		RSA_decrypt_file(keyname + '.enc', get_private_key(given_key))
		try:
			AES_decrypt_file(filename + '.aes', getkey(keyname), getiv())
		except:
			print('error: wrong private key')
		try:
			os.remove(keyname+'.enc')
		except: a = 1
		try:
			os.remove(filename+'.aes')
		except: a = 1
		try:
			os.remove(keyname)
		except: a = 1 # i dont care
	elif (mode == HASH):
		print(hash_code(filename))
	elif (mode == SETKEY):
		setkey()
	elif (mode == SETIV):	
		setiv()
	elif (mode == DEBUG_CREDENTIALS):
		get_credentials(debug=True)
	elif (mode == VIEW_REPORT):
		request = get_credentials()
		if (request != False):
			ret = view_report(request, report_id)
			if (not ret['bad_cred']):
				print('is public: ' + ret['public'])
				print('owner: ' + ret['owner'])
				print('created: ')
				print('        ' + ret['timestamp'])
				print('short description: ')
				print('        ' + ret['short'])
				print('long description: ')
				print('        ' + ret['long'])
				if (len(ret['files']) > 0):
					print('files:')
					for f in ret['files']:
						print('        ' + f + ': ' + ret['files'][f]["name"])
						print('                encrypted: ' + str(ret['files'][f]["encrypted"]))
				else:
					print('no files')
				if (len(ret['groups']) > 0):
					print('groups:')
					for g in ret['groups']:
						print('        '+g)
				else:
					print('no groups')
			else:
				mode = AUTH_FAILURE
		else:
			mode = AUTH_FAILURE
	elif (mode == LIST_REPORTS):
		request = get_credentials()
		if (request != False):
			ret = list_reports(request)
			for x in ret.keys():
				print(x + ": " + ret[x])
		else:
			mode = AUTH_FAILURE
	elif (mode == LIST_GROUP_REPORTS):
		request = get_credentials()
		if (request != False):
			ret = list_group_reports(request)
			for gname in ret:
				print("reports in " + gname + ":")
				for report in ret[gname]:
					print("        " + report + ": " + ret[gname][report])
		else:
			mode = AUTH_FAILURE
	elif (mode == LIST_PUBLIC_REPORTS):
		#~ request = get_credentials()
		#~ if (request != False):
			ret = list_public_reports()
			for x in ret.keys():
				print(x + ": " + ret[x])
		#~ else:
			#~ mode = AUTH_FAILURE
	elif (mode == DOWNLOAD_REPORT_FILE):
		request = get_credentials()
		if (request != False):
			ret = view_report(request, report_id)
			if (not ret['bad_cred']):
				file_id = -1
				if (len(ret['files']) > 0):
					print('files:')
					for k in ret['files'].keys():
						print('        ' + k + ': ' + ret['files'][k]["name"])
						print('                encrypted: ' + str(ret['files'][k]["encrypted"]))
					file_id = input("specify file id: ")
					filename = ret['files'][file_id]['url']
					#~ print(filename)
					download_report_file(request, report_id, file_id, filename)
				else:
					print('no files')
			else:
				mode = AUTH_FAILURE
		else:
			mode = AUTH_FAILURE
	elif (mode == UPLOAD_FDA):
		print('upload fda:')
		request = get_credentials()
		ret = request.post(BASE_URL + 'fda/upload-fda/', files={'fda': open('fda.py','rb')})
		print(ret.text)
	if (mode == AUTH_FAILURE):
		print("error: bad login credentials")

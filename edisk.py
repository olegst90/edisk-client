#!/usr/bin/env python

# Copyright (C) 2017  Oleg Stepanenko (olegst90@ukr.net)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import requests
import os
import sys
import json
import readline
import getpass
import hashlib

credfile=".edisk.cred"
#lastdirfile=".edisk.lastdir"


def login(session,relogin=False):
	if relogin is False:
		try:
			file = open(credfile,"r")
			cookies = json.load(file)
			file.close()
			#check?
			if "sid" not in cookies or "freemail" not in cookies:
				os.remove(credfile)
				raise "error"
			session.cookies = requests.cookies.cookiejar_from_dict(cookies)
			return True
		except:
			print "No valid credentials found, performing authentification..."

	while True:
		login = raw_input("Login:")
		secret = hashlib.sha1(getpass.getpass("Password:")).hexdigest()
		params =  {"callback" : "loginCallback",
		       "action" : "login",
		       "Login": login, 
		       "secret_digest":secret,
		       "level" :0
		      }
		rsp = session.get("https://mail.ukr.net/q/auth", params = params)
		cookies = rsp.cookies.get_dict();
		if "sid" not in cookies or "freemail" not in cookies:
			raw_input("Could not log in, press <enter> to try again...")
		else:
			break
	
	file = open(credfile,"w+")
	json.dump(cookies,file)
	file.close()
	return True
	

class EdiskAuthError:
	pass

def check_auth_err_or_raise(data):
	if "status" in data \
	    and type(data["status"]).__name__ == 'list' \
             and data["status"][0]["message"] == "NOT_AUTHORIZED":
				raise EdiskAuthError()

def get_storage(session,size):
	params = {"do": "GetStorage","size": size}
	rsp = session.get("http://edisk.ukr.net/api.php", params = params)
	items = rsp.text.split("#")
	if len(items) != 2:
		print "Could not get storage"
		return None
	else:
		print "Got {} bytes at {}#{}".format(size, items[0],items[1])
		return items[0], items[1]

#path: abs or rel to cwd
def get_node_info(session, path, cwd = 0):
	if path[0] == '/':
		dir = 0
	else:
		dir = cwd
	
	path_list = path.split("/")
	while '' in path_list:
		path_list.remove('')
	
	if len(path_list) == 0:
		return {"node":0, "node_type": "dir", "name":"root","created":0}
	
	for item in path_list[:-1]:
		params = {"do" : "Entries", "folder" : dir}
		rsp = session.get("http://edisk.ukr.net/api.php", params = params)
		data = json.loads(rsp.text)
		check_auth_err_or_raise(data)
		for entry_name, entry_meta in data["data"]["dirs"].items():
			if entry_meta["name"] == item:
					dir = entry_name[1:]
					break;
					
   	params = {"do" : "Entries", "folder" : dir}
	rsp = session.get("http://edisk.ukr.net/api.php", params = params)
	data = json.loads(rsp.text)
	check_auth_err_or_raise(data)
	entries = {}

	if data["data"]["files"] is not None:
		entries.update(data["data"]["files"])
	if data["data"]["dirs"] is not None:	
		entries.update(data["data"]["dirs"])
	
	for entry_name, entry_meta in entries.items():
		if entry_meta["name"] == path_list[-1]:
			res = entry_meta
			res.update({"node": entry_name[1:], "node_type": "file" if "type" in entry_meta else "dir"})
			return res
	
	raise IOError(path + " not found")
					
def list_entries(session,folder_node):
	params = {"do" : "Entries", "folder" : folder_node}
	rsp = session.get("http://edisk.ukr.net/api.php", params = params)
	data = json.loads(rsp.text)
	check_auth_err_or_raise(data)
	entries = {}
	if data["data"]["files"] is not None:
		entries.update(data["data"]["files"])
	if data["data"]["dirs"] is not None:	
		entries.update(data["data"]["dirs"])
	
	for entry_name, entry_meta in entries.items():
		res = entry_meta
		res.update({"node": entry_name[1:], "node_type": "file" if "type" in entry_meta else "dir"})
		yield res

def make_dir(session,path,cwd=0):
	if path[0] == '/':
		dir = 0
	else:
		dir = cwd
	
	path_list = path.split("/")
	while '' in path_list:
		path_list.remove('')
	
	if len(path_list) == 0:
		raise IOError("Can't create dir " + path)
	elif len(path_list) == 1:
		parent_node = dir
	else:
		parent_folder_path = "".join(path_list[:-1])
		print "parent folder path " + parent_folder_path
		parent_node = get_node_info(session,parent_folder_path, dir)["node"]
	
	filename = path_list[-1]	
	
	params = {"do":"MakeFolder", "parent": parent_node, "name" : filename}
	rsp = session.get("http://edisk.ukr.net/api.php", params = params)
	data = json.loads(rsp.text)
	check_auth_err_or_raise(data)
	if data["status"][0]["message"] == "FOLDER_CREATED":
		print path + " created"
	elif data["status"][0]["message"] == "FOLDER_EXISTS":
		raise IOError(path + " already exists")

def download(session,node_info,local_path):
	url = "http://edisk.ukr.net/get/{}/{}".format(node_info["node"],node_info["name"])
	rsp = session.get(url,stream=True)
	if rsp.status_code == 200:
		with open(local_path,'wb') as file:
			for chunk in rsp.iter_content(1024):
				file.write(chunk)
		print "OK"
		return
	print "Error " + rsp.status_code
	
def upload(session, local_path, remote_folder):
	statinfo = os.stat(local_path)
	fsize = statinfo.st_size
	srv,dev = get_storage(session,fsize)
	params = {"device_id":dev, "folder":remote_folder}
	data={"Filename":os.path.basename(local_path),
	       "Upload" : "Submit Query",
	       "auth"   : session.cookies.get_dict()["freemail"]
	       }
	files = {'upload' : open(local_path,'r')}       
	rsp = session.post("http://"+srv+"/store.php",params=params, files=files, data=data)
	print rsp
							
def command(session,cmd,args=[],current_dir=0):
	attempts = 0
	while True:
		try:
			if cmd == "ls":
				try:
					entry = get_node_info(session, args[0],current_dir)
					if entry["node_type"] == "dir":
						for i in list_entries(session,entry["node"]):
							print i
					else:
						print "File " + str(entry)
				except IOError as e:
					print e
					break
			
			elif cmd == "mkdir":
				try:
					for d in args:				
						make_dir(session, d, current_dir)
				except IOError as e:
					print e
					break
			
			elif cmd == "download":
				try:
					entry = get_node_info(session, args[0],current_dir)
					if entry["node_type"] == "dir":
						print args[0] + " is a directory"
					else:
						print "Downloading " + args[0]
						download(session,entry,args[1])
				except IOError as e:
					print e
					break

			elif cmd == "upload":
				try:
					entry = get_node_info(session, args[1],current_dir)
					if entry["node_type"] == "dir":
						print "Uploading {} to {}".format(args[0],args[1])
						upload(session,args[0],entry["node"])
					else:
						print args[1] + " is a directory"
				except IOError as e:
					print e
					break
					
			elif cmd == "rm":
				try:
					a = raw_input("Delete files/folders? ").lower()
					if a != "y" and a != "yes":
						break
					files = []
					folders = []
					for path in args:
						entry = get_node_info(session, path, current_dir)
						if entry["node_type"] == "dir":
							folders.append(entry["node"])
						else:
							files.append(entry["node"])
					
					files = ",".join(files)
					folders = ",".join(folders)
					
					params = {"do" : "Delete", "folders" : folders, "files": files}
					rsp = session.get("http://edisk.ukr.net/api.php", params = params)
					data = json.loads(rsp.text)
					check_auth_err_or_raise(data)
					if "status" in data \
					       and type(data["status"]).__name__ == 'list' \
								and data["status"][0]["message"] == "DELETED":
						print "Deleted: " + " ".join(args)
				except IOError as e:
					print e
					break				
			break
				
		except EdiskAuthError as e:
			if(attempts < 1):
				print "login again"
				login(s)
				attempts += 1
				continue
			else:
				print "had enough"
				break
		
if len(sys.argv) < 3 or sys.argv[1] == "help":
	print "Usage: " + sys.argv[0] + " <cmd> [args]"
	print "Commands:"
	print "  ls REMOTE_DIR"
	print "  mkdir REMOTE_DIR"
	print "  upload LOCAL_PATH REMOTE_DIR"
	print "  download REMOTE_PATH LOCAL_PATH"
	print "  rm REMOTE_PATH[,REMOTE_PATH2[,...]]"
	exit()
	
s = requests.Session()
login(s,relogin=False)
command(s,sys.argv[1],sys.argv[2:])











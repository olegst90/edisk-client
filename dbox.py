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

import dropbox
import json
import sys
import os

app_key = 'eyrfiy0gctt906b'
app_secret = 'xwqcb222j85rjm1'

def login():
    credpath = os.path.expanduser('~') + "/.dbox"
    if not os.path.exists(credpath):
        os.mkdir(credpath)
    credfile = credpath + "/.dbox.cred"
    try:
        file = open(credfile,"r");
        cred = json.load(file);
        file.close();
        print "Reusing existing credentials"
        return cred["access_token"], cred["user_id"]
    except IOError as e:
        print "Could not read credentials"
        
    flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)
    authorize_url = flow.start()
    print '1. Go to: ' + authorize_url
    print '2. Click "Allow" (you might have to log in first)'
    print '3. Copy the authorization code.'
    code = raw_input("Enter the authorization code here: ").strip()
    access_token, user_id = flow.finish(code)
    file = open(credfile,"w+")
    json.dump({"access_token" : access_token, "user_id" : user_id}, file)
    file.close()
    return access_token, user_id

def help():
	print "Usage: " + sys.argv[0] + " <cmd> [args]"
	print "Commands:"
	print "  ls REMOTE_DIR"
	print "  mkdir REMOTE_DIR"
	print "  upload LOCAL_PATH REMOTE_DIR"
	print "  download REMOTE_PATH LOCAL_PATH"
	print "  rm REMOTE_PATH[,REMOTE_PATH2[,...]]"
	
if len(sys.argv) < 3:
    help()
    exit(-1)
elif sys.argv[1] == "help":
    help()
    exit()
    
access_token, user_id = login()
client = dropbox.client.DropboxClient(access_token)
print 'linked account: ', client.account_info()

cmd = sys.argv[1]
args = sys.argv[2:]

try:
    if cmd == "ls":
        meta = client.metadata(args[0])
        print meta
    elif cmd == "mkdir":
        meta = client.file_create_folder(args[0])
        print meta
    elif cmd == "rm":
        meta = client.file_delete(args[0])
        print meta
    elif cmd == "upload":
        f = open(args[0],"rb");
        meta = client.put_file(args[1] + "/" + os.path.basename(args[0]),f)
        print meta
    elif cmd == "download":
        f = open(args[1],"wb");
        with client.get_file(args[0]) as stream:
            f.write(stream.read())
        f.close()
    else:
        help()
        exit(-1)
except (dropbox.rest.ErrorResponse, IOError) as e:
    print ("Operation failed: " + str(e))
    exit(-1)
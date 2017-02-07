# edisk-client

edisk-client is a basic command line tool written in Python 
to wirk with EDisk service (http://edisk.ukr.net) provided by http://ukr.net.
To get it working, you need an existing account on ukr.net.

The tool will request your login credentials as needed. 
Authentification info wil be stored in .edisk.cred file.
It includes cookies issued upon authentification. No 
passwords are stored - neither plain or hashed.

```
Usage: ./edisk.py <cmd> [args]
Commands:
  ls REMOTE_DIR
  mkdir REMOTE_DIR
  upload LOCAL_PATH REMOTE_DIR
  download REMOTE_PATH LOCAL_PATH
  rm REMOTE_PATH[,REMOTE_PATH2[,...]]
```

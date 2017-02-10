# edisk-client

edisk-client is a basic command line tool written in *Python* 
to work with online file storage services. Currently [*Dropbox*](https://dropbox.com) and [*EDisk*](http://edisk.ukr.net) services are supported.
To get it working, you need an existing account.

The tool will request your login credentials as needed. 
Authentification info wil be stored in a file within the working directory.
It includes cookies or tokens issued upon authentification. No 
passwords are stored - neither plain or hashed.

For the *Dropbox* script, you will need dropbox package:
````
pip install dropbox
```
Both clients support similar CLI commands:
```
Usage: ./edisk.py|./dbox.py <cmd> [args]
Commands:
  ls REMOTE_DIR
  mkdir REMOTE_DIR
  upload LOCAL_PATH REMOTE_DIR
  download REMOTE_PATH LOCAL_PATH
  rm REMOTE_PATH[,REMOTE_PATH2[,...]]
```

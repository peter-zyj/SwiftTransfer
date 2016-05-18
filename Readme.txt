the Abstract:
transfer all resource by the interface of Swift/Swauth

the prerequisites for the tool running:

1. Python 2.7.* (CentOS7 has the version by default, CentOS6 need to upgrade python 2.6 to 2.7 manually)

2. Replace Python original Lib File with New Update one : socket.by

(centos 6 : /usr/local/lib/python2.7/socket.py  or /usr/lib64/python2.6/socket.py)

(centos 7 : /usr/lib64/python2.7/socket.py)
usage:

1. example: %prog -o "192.168.24.210,192.168.24.211...." -d "192.168.24.218,192.168.24.219....." -r <all | account | user | container>

2. example: %prog -o "192.168.24.210,192.168.24.211...." -d "192.168.24.218,192.168.24.219....." -s <"account::user::container">

 

3. -o "..." == CDE470's Cache/Video IP Ports (source COS nodes)

  -d "..." == 3160's Cache/Video IP Ports (destination COS nodes)
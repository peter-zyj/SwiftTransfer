# -*- coding: utf-8 -*- 

__author__ = 'yijunzhu'

import os, sys, re
import time, datetime
#import request
import httplib,urllib2,random
import subprocess, optparse
import socket
from select import select
from multiprocessing import Process, Queue, Manager,Array, Lock
import fcntl, functools
import struct,signal,traceback


#####
#add lock for process number
#add the netmask configuration
#fix the bug of statistics of "Done" object
#save previous old records
# internal release version for V10
# fix the bug of records and iteration of account
# fix the bug of global obj number statistic
# fix the protection mechanism
#
#Internal Version:9
#bug gix for 10K limit
#more than10K  object, save Time for MD5 reading
#defined as the big file handler
#add filter by specified resource 
#####

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(\
        s.fileno(),\
        0x8915,\
        struct.pack('256s', ifname[:15])\
    )[20:24])



class BoundHTTPHandler(urllib2.HTTPHandler):

    def __init__(self, source_address=None, debuglevel=0):
        urllib2.HTTPHandler.__init__(self, debuglevel)
        self.http_class = functools.partial(httplib.HTTPConnection,
                source_address=source_address)

    def http_open(self, req):
        return self.do_open(self.http_class, req)



class phaseBook:
    def __init__(self):
        self.account = []
        self.user = []
        self.container = []
        self.object = []
        self.md5 = []
        self.transferRead = []
        self.currentPhase = ""

    def setPhaseTime(self, phase):
        self.currentPhase = phase

    def addAccountSessionList(self,ACTprocess):
        self.account.append(ACTprocess)

    def addUserSessionList(self,USRprocess):
        self.user.append(USRprocess)

    def addContainerSessionList(self,CONTprocess):
        self.container.append(CONTprocess)

    def addObjectSessionList(self,OBJprocess):
        self.object.append(OBJprocess)

    def addMD5SessionList(self,MD5process):
        self.md5.append(MD5process)

    def addTransferReadSessionList(self,TRSprocess):
        self.transferRead.append(TRSprocess)

class transferSession:
    def __init__(self, account):
        self.account = account
        self.accountid = ''
        self.user = {}
        self.container = {}
        self.object = []
        self.XferTag = False
        self.numACT = 0
        self.numUSR = 0
        self.numCONT = 0
        self.numOBJ = 0

        self.accountMeta = {}
        self.containerMeta = {}
        self.objectMeta = {}

    def getObject(self):
        return self.object
    def getContainer(self):
        return self.container
    def getAccount(self):
        return self.account
    def getUser(self):
        return self.user
    def getTag(self):
        return self.XferTag
    def getAccountID(self):
        return self.accountid
    def GetObjectNumber(self,containerName):
        return self.container[containerName]["objNum"]

    def setObj(self,object):
        self.object = object
    def setContainer(self,container):
        self.container = container
    def setAccount(self,account):
        self.account = account        
    def setUser(self,user):
        self.user = user
    def setTag(self,tag):
        self.XferTag = tag
    def setAccountID(self,accountid):
        self.accountid = accountid
    def SetObjectNumber(self,containerName,number):
        self.container[containerName]["objNum"] = number


    def addUser(self,userName):
        self.user[userName] = {}
    def addUserList(self,userList):
        for user in userList :
            self.user[user] = {}
    def addUserProperty(self,userName,prop):
        self.user[userName] = prop
    def addContainer(self,containerName):
        self.container[containerName] = {}
        self.container[containerName]["objNum"] = 0
        self.container[containerName]["objFullDict"] = {}
        self.objectMeta[containerName] = {}
    def addObjList(self,containerName,objList):
        for obj in objList:
            self.container[containerName]["objFullDict"][obj] = ''
            self.objectMeta[containerName][obj] = {}
        self.object += objList
    def addObj(self,containerName,objName):
        if objName in self.container[containerName]["objFullDict"].keys():
            return
        else:
            self.container[containerName]['objFullDict'][objName] = ''
            self.object += objList


def recordsMap():
    global newcontent,records
    if records == "":
        return
    try:
        content = "".join(records.values())
        newcontent += content
    except:
        e = sys.exc_info()[0]
        print "<p>Error: %s</p>" % e
        print traceback.print_exc()

def autoTuning(phase,ses,orgIPL,destIPL=None):
    tuningDict = {}
    if phase == "object":
        loopType = configure["objLoop"]
        proType = configure["objProcess"]
    elif phase == "md5":
        loopType = configure["md5Loop"]
        proType = configure["md5Process"]

    for container in ses.getContainer().keys():
        portCap = loopType*proType
        tuningDict[container] = {}
        tempLoop = loopType
        if destIPL != None:
            portNum = min(len(orgIPL),len(destIPL))
        else:
            portNum = len(orgIPL)
        num = int(ses.GetObjectNumber(container))

        if loopType == 0:
            tempLoop = num/(portNum*proType)
        else:
            while True:
                if  num < portCap*portNum and num != 0:
                    tempLoop = tempLoop/2
                    portCap = tempLoop*proType
                else:
                    break

        if tempLoop == 0:
          if loopType != 0:
              tempLoop = loopType
          else:
              tempLoop = 200


        if phase == "object":
            tuningDict[container]["objLoop"] = tempLoop
        elif phase == "md5":
            tuningDict[container]["md5Loop"] = tempLoop
    return tuningDict




def signal_handler(signum, frame):
    global newcontent,oldcontent,objDict,orgIPL,destIPL,pidDict,records
    global PB
    print("Mannual Stop has been Detected")
    try:
        recordsMap()
    except IOError:
            print "Manager's Pipe broken"
    except ValueError:
            print "Missing one memeber in the crew"

    if PB.currentPhase == "Account":
        for item in PB.account:
            item.close()
    elif PB.currentPhase == "User":
        for item in PB.user:
            item.close()
    elif PB.currentPhase == "Container":
        for item in PB.container:
            item.close()
    elif PB.currentPhase == "Object":
        for item in PB.object:
            item.close()            
    elif PB.currentPhase == "MD5":
        for item in PB.md5:
            item.terminate()
    elif PB.currentPhase == "TransferRead":
        for item in PB.transferRead:
            item.terminate()                       
                
    timeTag = time.strftime('%Y-%m-%d#%H:%M:%S', time.localtime(time.time()))
    milliTag = datetime.datetime.now().microsecond
    file = open('Xsfer.log_%s_%s' % (timeTag,milliTag), 'w+')
    file.write(newcontent)
    file.close()

    loopPID = os.getpid()
    if loopPID == pidDict["Main"]:
#       os.popen("killall python")
        os.popen("ps -ef | grep 'python %s' | grep -v grep | awk '{print$2}' | xargs kill" % (sys.argv[0]))
        sys.exit(0)







def read_handler(signum, frame):
    raise

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGALRM, read_handler)

def Execute(scope,spec,orgPortL,destPortL):
    global oldcontent,newcontent,orgIPL,destIPL,objDict,pidDict,configure
    global numAccount,numUser,numContainer,numObject,records
    global PB

    linuxRecIP = {}
    linuxSndIP = {}
    for x  in orgPortL:
        linuxRecIP[get_ip_address(x)]=x
    for y  in destPortL:
        linuxSndIP[ get_ip_address(y)] = y

    global PB
    PB = ""
    PB = phaseBook()

    oldToken,contentSessionList = ResPEP(orgIPL,destIPL,scope,spec,linuxRecIP)
    act_job = []
    usr_job = []
    cont_job = []
    obj_job = []



    token = ''
    destIP = random.choice(destIPL).strip()
    req_N_tk = urllib2.Request('http://%s/v1.0/' % (destIP))
    req_N_tk.add_header('X-auth-user', '.super_admin')
    req_N_tk.add_header('X-auth-key', 'rootroot')
    resp_N_tk = urllib2.urlopen(req_N_tk)
    token = resp_N_tk.info().getheader('X-Auth-Token')
    resp_N_tk.close()
    #Super token for new Device


    manager_act = Manager()
    actDict = manager_act.dict()
    newcontent = newcontent.replace("ACCOUNT##","")
    for ses in contentSessionList:
         act = ses.getAccount()
         actid = ses.getAccountID()
         finalString = "%s:yes:END" % (actid)
         oldString = "%s:no:END" % (actid)
         newString = "%s:ongoing:END" % (actid)
         if finalString not in oldcontent:
             newcontent = newcontent.replace(oldString,newString)
             key = actid
             actDict[key] = ""
             print "Remaining Resource:Account[%d]-User[%d]-Container[%d]-object[%d]" % (numAccount,numUser,numContainer,numObject)
             p = Process(target=AccountCreation, args=(actDict,destIPL,ses,token,contentSessionList))
             p.start()
             act_job.append(p)
         else:
            newcontent = newcontent.replace(oldString,finalString)
            ses.numACT -= 1
            numAccount -= 1
            continue

         for key in actDict.keys():
            if actDict[key] not in ["","checked"]:
                actid = key
                finalString = "%s:yes:END" % (actid)
                oldString = "%s:no:END" % (actid)
                newString = "%s:ongoing:END" % (actid)
                newcontent = newcontent.replace(newString,finalString)
                ses.numACT -= 1
                numAccount -= 1
                actDict[key] = "checked"



    for p in act_job:
         p.join()

    for key in actDict.keys():
        if actDict[key] not in ["","checked"]:
            actid = key
            finalString = "%s:yes:END" % (actid)
            oldString = "%s:no:END" % (actid)
            newString = "%s:ongoing:END" % (actid)
            newcontent = newcontent.replace(newString,finalString)
            ses.numACT -= 1
            numAccount -= 1
            actDict[key] = "checked"

    print "#################New act done#########################"
    if scope == 'account':
        raise KeyboardInterrupt
        return 1
     #step4:swauth: new Account created in the system


    manager_usr = Manager()
    usrDict = manager_usr.dict()
    newcontent = newcontent.replace("USER##","")
    for ses in contentSessionList:
         for usr in ses.getUser():
             actid = ses.getAccountID()
             finalString = "%s-user@%s:yes:END" % (actid,usr)
             oldString = "%s-user@%s:no:END" % (actid,usr)
             newString = "%s-user@%s:ongoing:END" % (actid,usr)
             if finalString not in oldcontent:
                 newcontent = newcontent.replace(oldString,newString)
                 key = "%s:user@%s" % (actid,usr)
                 usrDict[key] = ""
                 print "Remaining Resource:Account[%d]-User[%d]-Container[%d]-object[%d]" % (numAccount,numUser,numContainer,numObject)
                 p = Process(target=UserCreation, args=(usrDict,destIPL,ses,usr,contentSessionList))
                 p.start()
                 usr_job.append(p)
             else:
                newcontent = newcontent.replace(oldString,finalString)
                ses.numUSR -= 1
                numUser -= 1
                continue

         for key in usrDict.keys():
            if usrDict[key] not in ["","checked"]:

                actid,usr = key.split(':')
                usr = usr.replace("user@","")
                finalString = "%s-user@%s:yes:END" % (actid,usr)
                oldString = "%s-user@%s:no:END" % (actid,usr)
                newString = "%s-user@%s:ongoing:END" % (actid,usr)
                newcontent = newcontent.replace(newString,finalString)
                ses.numUSR -= 1
                numUser -= 1
                usrDict[key] = "checked"

    for p in usr_job:
         p.join()

    for key in usrDict.keys():
        if usrDict[key] not in ["","checked"]:

            actid_rec,usr_rec = key.split(':')
            usr_rec = usr.replace("user@","")
            finalString = "%s-user@%s:yes:END" % (actid_rec,usr_rec)
            oldString = "%s-user@%s:no:END" % (actid_rec,usr_rec)
            newString = "%s-user@%s:ongoing:END" % (actid_rec,usr_rec)
            newcontent = newcontent.replace(newString,finalString)
            ses.numUSR -= 1
            numUser -= 1
            usrDict[key] = "checked"


    print "#################New usr done#########################"
    if scope == 'user':
        raise KeyboardInterrupt
        return 1
     #step5:swauth: new User created in the system

    manager_cont = Manager()
    contDict = manager_cont.dict()

    newcontent = newcontent.replace("CONTAINER##","")
    for ses in contentSessionList:
        for container in ses.getContainer().keys():
             actid = ses.getAccountID()
             finalString = "%s-%s:yes:END" % (actid,container)
             oldString = "%s-%s:no:END" % (actid,container)
             newString = "%s-%s:ongoing:END" % (actid,container)
             if finalString not in oldcontent:
                newcontent = newcontent.replace(oldString,newString)
                key = "%s:%s" % (actid,container)
                contDict[key] = ""
                print "Remaining Resource:Account[%d]-User[%d]-Container[%d]-object[%d]" % (numAccount,numUser,numContainer,numObject)
                p = Process(target=ContainerCreation, args=(contDict,destIPL,ses,container,token,contentSessionList))
                p.start()
                cont_job.append(p)
             else:
                newcontent = newcontent.replace(oldString,finalString)
                ses.numCONT -= 1
                numContainer-= 1
                continue

             for key in contDict.keys():
                 if contDict[key] not in ["","checked"]:
                    actid_rec,container_rec = key.split(':')
                    finalString = "%s-%s:yes:END" % (actid_rec,container_rec)
                    oldString = "%s-%s:no:END" % (actid_rec,container_rec)
                    newString = "%s-%s:ongoing:END" % (actid_rec,container_rec)
                    newcontent = newcontent.replace(newString,finalString)
                    ses.numCONT -= 1
                    numContainer -= 1
                    contDict[key] = "checked"

    for p in cont_job:
        p.join()  

    for key in contDict.keys():
        if contDict[key] not in ["","checked"]:
            actid,container = key.split(':')
            finalString = "%s-%s:yes:END" % (actid,container)
            oldString = "%s-%s:no:END" % (actid,container)
            newString = "%s-%s:ongoing:END" % (actid,container)
            newcontent = newcontent.replace(newString,finalString)
            ses.numCONT -= 1
            numContainer -= 1
            contDict[key] = "checked"


    print "#################New container done#########################"
    if scope == 'container':
        raise KeyboardInterrupt
        return 1
        #step6:swift: new container created in the system

    PB.setPhaseTime("TransferRead")
    manager_obj = Manager()
    numDict = manager_obj.dict()

    manager_obj2 = Manager()
    objDict = manager_obj2.dict()
    objDict['obj'] = numObject
    objDict['cont'] = numContainer
    objDict['act'] = numAccount
    objDict['usr'] = numUser
    objDict['token'] = token
    objDict["oldToken"] = oldToken

    manager_obj3 = Manager()
    records = manager_obj3.dict()

    for ip in orgIPL:
        numDict[ip] = configure["objProcess"]
    for ip in destIPL:
        numDict[ip] = configure["objProcess"]
    lock = Lock()

    idx = 0
    step = configure["objLoop"]

    newcontent = newcontent.replace("OBJECT##","")
    for ses in contentSessionList:
        #auto change the steps for each container
        tuningDict = autoTuning("object",ses,orgIPL,destIPL)
        for container in ses.getContainer().keys():
            inx = 0

            step = int(tuningDict[container]["objLoop"])
            loopTime = int(ses.GetObjectNumber(container))/step if (int(ses.GetObjectNumber(container))%step==0) else int(ses.GetObjectNumber(container))/step+1
            for x in range(loopTime):
                while True:
                    orgIP = random.choice(orgIPL).strip()
                    destIP = random.choice(destIPL).strip()
                    orgCheck = numDict[orgIP] - 1
                    destCheck = numDict[destIP] - 1
                    if orgCheck >= 1 and destCheck >=1:
                        with lock:
                            numDict[destIP] -= 1
                            numDict[orgIP] -= 1
                        numObject = objDict["obj"]
                        token = objDict['token']
                        oldToken = objDict['oldToken']
#                       print "Remaining Resource:Account[%d]-User[%d]-Container[%d]-object[%d]" % (numAccount,numUser,numContainer,numObject)
                        p = Process(target=ObjectCreationBatch, args=(lock,objDict,numDict,records,orgIP,destIP,linuxRecIP,linuxSndIP,ses,container,contentSessionList,idx,inx,step,oldcontent))
                        p.start()
                        obj_job.append(p)
                        PB.addTransferReadSessionList(p)
                        break
                    else:
#                       print "Debug::ZYJ::Queue Hit Full::",numDict
                        continue

#               recordsMap()
                idx += 1
                inx += 1

    for p in obj_job:
        p.join()

    print("Complete the DATA transfer!")
    timeTag = time.strftime('%Y-%m-%d#%H:%M:%S', time.localtime(time.time()))
    print timeTag
    recordsMap()

    timeTag = time.strftime('%Y-%m-%d#%H:%M:%S', time.localtime(time.time()))
    print timeTag
    milliTag = datetime.datetime.now().microsecond
    file = open('Xsfer.log_%s_%s' % (timeTag,milliTag), 'w+')
    file.write(newcontent)
    file.close()
    os.popen("ps -ef | grep 'python %s' | grep -v grep | awk '{print$2}' | xargs kill" % (sys.argv[0]))
    sys.exit(0)
    return 1

        #step7:swift: new objects created in the system


def ObjectCreationBatch(lock,objDict,numDict,records,orgIP,destIP,linuxRecIP,linuxSndIP,ses,container,contentSessionList,idx,inx,step,oldcontent):
        listPart = ses.getContainer()[container]["objFullDict"].keys()[inx*step:(inx+1)*step]
        records[idx] = ""
        for object in listPart:
            while True:
                 actid = ses.getAccountID()
                 finalString = "%s-%s-%s:yes:END" % (actid,container,object)
                 oldString = "%s-%s-%s:no:END" % (actid,container,object)
                 newString = "%s-%s-%s:ongoing:END" % (actid,container,object)

                 if finalString not in oldcontent:
                    records[idx] += newString + os.linesep
#                   tempDict = dict(numDict)
                    try:
                        numObject = objDict['obj']
                        numContainer = objDict['cont']
                        numAccount = objDict['act']
                        numUser = objDict['usr']
                        print "Remaining Resource:Account[%d]-User[%d]-Container[%d]-object[%d]" % (numAccount,numUser,numContainer,numObject)
                        ObjectCreation(objDict,numDict,orgIP,destIP,linuxRecIP,linuxSndIP,ses,container,object,contentSessionList)
                        records[idx] = records[idx].replace(newString,finalString)
                    except:
                        continue
                    break
                 else:
                    records[idx]  += finalString + os.linesep
                    objDict["obj"] -= 1
                    print "already Done::",actid,container,object
                    break

        with lock:
            numDict[orgIP] += 1
            numDict[destIP] += 1




def ObjectCreation(objDict,numDict,orgIP,destIP,linuxRecIP,linuxSndIP,ses,container,object,contentSessionList):
    addTag = True
    token = objDict['token']
    oldToken = objDict['oldToken']
    ipR = random.choice(linuxRecIP.keys())
    devR = linuxRecIP[ipR]
    handler = BoundHTTPHandler(source_address=(ipR, 0, devR))
    openerR = urllib2.build_opener(handler)
    newActID = "AUTH_" + ses.getAccountID()
    req_O_obj = urllib2.Request('http://%s/v1/%s/%s/%s' % (orgIP, newActID, container, object))
    req_O_obj.add_header('x-auth-token', oldToken)
    req_O_obj.get_method = lambda: 'GET'

    newActID = "AUTH_"+ses.getAccountID()
    ipS = random.choice(linuxSndIP.keys())
    devS = linuxSndIP[ipS]
    handler = BoundHTTPHandler(source_address=(ipS, 0, devS))
    openerW = urllib2.build_opener(handler)
    req_N_obj = urllib2.Request('http://%s/v1/%s/%s/%s' % (destIP, newActID, container, object))
    req_N_obj.add_header('x-auth-token', token)
    req_N_obj.get_method = lambda: 'HEAD'

    WriteMSG = "PUT /v1/%s/%s/%s HTTP/1.1\r\n" % (newActID,container,object)
    WriteMSG += "User-Agent: Yijun\r\n"
    WriteMSG += "x-auth-token: %s\r\n" % (token)
    if ses.objectMeta[container][object] != {}:
        for meta in ses.objectMeta[container][object]:
            value = ses.objectMeta[container][object][meta]
            WriteMSG += "%s: %s\r\n" % (meta,value)
    WriteMSG += "Host: %s\r\n" % (ip)
    WriteMSG += "Content-Length: %s\r\n" % (ses.getContainer()[container]["objFullDict"][object][1])
    WriteMSG += "Accept: */*\r\n"
    WriteMSG += "Expect: 100-continue\r\n"
    WriteMSG += "\r\n"


    while True:
        try:
            print "Debug::Ingesting1::", container+'/'+object
            try:
                resp_O_obj = openerR.open(req_O_obj)
            except urllib2.HTTPError as e:
                if e.code == 401:
                    oldToken = TokenFetch(orgIP)
                    objDict["oldToken"] = oldToken
                    req_O_obj.add_header('x-auth-token', oldToken)
                    resp_O_obj= urllib2.urlopen(req_O_obj)
                else: #other error code for read
                    break

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, 25, devS)
            s.bind((ipS,0))
            s.connect((destIP,80))
            s.send(WriteMSG)
            resp = s.recv(1024)
            exTag = 0
            if "100 Continue" in resp:
                while True:
                    
                    try:
                        signal.alarm(5)                                                                                                                                                                   
                        content=resp_O_obj.read(87380)
                        signal.alarm(0)
                    except:
                        resp_O_obj.close()
                        s.close()
                        exTag = 1
                        break

                    if content != "":                    
                        s.send(content)
                    else:
                        try:
                            resp_N_md5 = openerW.open(req_N_obj)
                        except urllib2.HTTPError as e:
                            if e.code == 401:
                                token = TokenFetch(destIP)
                                objDict["token"] = token
                                req_N_obj.add_header('x-auth-token', token)
                                resp_N_md5= urllib2.urlopen(req_N_obj)

                        try:
                            md5 = resp_N_md5.info().getheader('ETag').replace('"','')
                            resp_O_obj.close()
                            s.close()

                        except:
                            print "NO MD5==Not finish for the object",container+'/'+object
                            resp_N_md5.close()
                            continue
                        break  

            elif "401 Unauthorized" in resp:
                resp_O_obj.close()
                s.close()
                token = TokenFetch(destIP)
                objDict["token"] = token
                WriteMSG = re.sub(r'(?<=x-auth-token: ).*?(?=\r\n)',token,WriteMSG)
                continue

            else:
                if ses.getContainer()[container]["objFullDict"][object][1]=="0":
                    try:
                        resp_N_md5 = openerW.open(req_N_obj)
                    except:
                        token = TokenFetch(destIP)
                        req_N_obj.add_header('x-auth-token', token)
                        resp_N_md5 = openerW.open(req_N_obj)
                    try:
                        md5 = resp_N_md5.info().getheader('ETag').replace('"','')
                        resp_O_obj.close()
                        s.close()

                    except:
                        print "NO MD5==Not finish for the object",container+'/'+object
                        resp_N_md5.close()
                        continue
                    break
                else:
                    resp_O_obj.close()
                    s.close()
                    time.sleep(10)
                    continue

            if exTag == 1:
                continue

            print "MD5::",container+'/'+object
            if md5 == ses.getContainer()[container]["objFullDict"][object][0]:
                resp_N_md5.close()

                objDict["obj"] -= 1 

                break
            else:
                print "Debug:zyj:MD5-ERR::",container+'/'+object
                continue
        except:
            print "Socket meet with issue!!!!!!!!!!!!!!!!!!!!!!!!!"
            e = sys.exc_info()[0]
            print "<p>Error: %s</p>" % e
            print traceback.print_exc()
            continue






def AccountCreation(actDict,destIPL,ses,token,contentSessionList):
    while True:
        try:
            newAct = ses.getAccount()
            newActID = ses.getAccountID()

            destIP = random.choice(destIPL).strip()
            req_N_act = urllib2.Request('http://%s/auth/v2/%s' % (destIP,newAct))
            req_N_act.add_header('X-Auth-Admin-User', '.super_admin')
            req_N_act.add_header('X-Auth-Admin-Key', 'rootroot')
            req_N_act.add_header('X-Account-Suffix', newActID)
            req_N_act.get_method = lambda: 'PUT'
            resp_N_act = urllib2.urlopen(req_N_act)
            actDict[ses.getAccountID()]="yes"

            req_N_actMeta = urllib2.Request('http://%s/v1/%s' % (destIP, "AUTH_"+newActID))
            req_N_actMeta.add_header('x-auth-token', token)
            req_N_actMeta.get_method = lambda: 'POST'
            if ses.accountMeta != {}:
                for meta in ses.accountMeta:
                    req_N_actMeta.add_header(meta, ses.accountMeta[meta])


            try:
                resp_N_actMeta = urllib2.urlopen(req_N_actMeta)
            except urllib2.HTTPError as e:
                if e.code == 401:
                    token = TokenFetch(destIP)
                    req_N_actMeta.add_header('x-auth-token', token)
                    resp_N_actMeta= urllib2.urlopen(req_N_actMeta)
            break
        except:
            continue
    resp_N_act.close()
    resp_N_actMeta.close()


def UserCreation(usrDict,destIPL,ses,user,contentSessionList):
    while True:
        try:
            newAct = ses.getAccount()
            destIP = random.choice(destIPL).strip()
            req_N_usr = urllib2.Request('http://%s/auth/v2/%s/%s' % (destIP,newAct,user))
            req_N_usr.add_header('X-Auth-Admin-User', '.super_admin')
            req_N_usr.add_header('X-Auth-Admin-Key', 'rootroot')
            if ses.user[user]['name'] == ".reseller_admin":
                req_N_usr.add_header('X-Auth-User-Reseller-Admin', 'true')
            elif ses.user[user]['name'] == ".admin":
                req_N_usr.add_header('X-Auth-User-Admin', 'true')

            if ses.user[user]['auth'] != ['']:
                req_N_usr.add_header('X-Auth-User-Key', ses.user[user]['auth'][0])

            req_N_usr.get_method = lambda: 'PUT'
            resp_N_usr = urllib2.urlopen(req_N_usr)

            key = "%s:user@%s" % (ses.getAccountID(),user)
            usrDict[key] = "yes"
            break
        except:
            continue
    resp_N_usr.close()


def ContainerCreation(contDict,destIPL,ses,container, token,contentSessionList):
    while True:
        try:
            newActID = "AUTH_"+ses.getAccountID()
            destIP = random.choice(destIPL).strip()
            req_N_cont = urllib2.Request('http://%s/v1/%s/%s' % (destIP, newActID, container))
            req_N_cont.add_header('x-auth-token', token)
            req_N_cont.add_header('x-auth-token', token)
            req_N_cont.get_method = lambda: 'PUT'
            if ses.containerMeta[container] != {}:
                for meta in ses.containerMeta[container]:
                    req_N_cont.add_header(meta, ses.containerMeta[container][meta])

            try:
                resp_N_cont = urllib2.urlopen(req_N_cont)
            except urllib2.HTTPError as e:
                if e.code == 401:
                    token = TokenFetch(destIP)
                    req_N_cont.add_header('x-auth-token', token)
                    resp_N_cont= urllib2.urlopen(req_N_cont)

            key = "%s:%s" % (ses.getAccountID(),container)
            contDict[key] = "yes"
            break
        except:
            continue
    resp_N_cont.close()




def TokenFetch(IP):
    req_tk = urllib2.Request('http://%s/v1.0/' % (IP))
    req_tk.add_header('X-auth-user', '.super_admin')
    req_tk.add_header('X-auth-key', 'rootroot')
    resp_tk = urllib2.urlopen(req_tk)
    token = resp_tk.info().getheader('X-Auth-Token')
    resp_tk.close()
    return token
    

def ResPEP(orgIPL,destIPL,scope,spec,linuxRecIP):
    global file,newcontent,oldcontent,configure
    global numAccount,numUser,numContainer,numObject,pidDict
    global PB
    newcontent = "MAIN##MD5##ACCOUNT##USER##CONTAINER##OBJECT##END##"+os.linesep
	#step1:: clarify the scope

    print "debug:zyj:scope::",scope
    print "debug:zyj:spec::",spec
    print "debug:zyj:orgIP::",orgIPL
    print "debug:zyj:destIP::",destIPL
    specResource = ""
    scopeResource = ""
    if "::" in spec:
        specResource = spec.split("::")
        if len(specResource)>4 or len(specResource)==0:
            print "error hit for the resource format specified,exp:  account[::[user| ][::[container| ][::object]]] "
            sys.exit(1)
    else:
        if scope.upper() != 'ALL':
            scopeResource = scope
        else:
            pattern = None
            scopeResource = "all"
    print "@@@@@@@@@@@@@@@@@"
    print scopeResource
    print specResource
    print "@@@@@@@@@@@@@@@@@"
    #step2.1:swauth: list all the account availabe in the system
    PB.setPhaseTime("Account")
    contentSessionList = []
    accountList = []
    pattern_act = r'(?<="name": \").*?(?=\")'
    orgIP = random.choice(orgIPL).strip()
    if specResource != "" and scopeResource == "":
        req_act = urllib2.Request('http://%s/auth/v2/%s' % (orgIP,specResource[0].strip()))
    else:
        req_act = urllib2.Request('http://%s/auth/v2/' % (orgIP))

    req_act.add_header('X-Auth-Admin-User', '.super_admin')
    req_act.add_header('X-Auth-Admin-Key', 'rootroot')
    try:
        resp_act = urllib2.urlopen(req_act)
    except urllib2.HTTPError as e:
        if e.code == 404:
            print "not found the account::",specResource[0].strip()
            sys.exit(1)
    PB.addAccountSessionList(resp_act)
    if specResource != "" and scopeResource == "" and specResource[0].strip() != "":
        accountList = [specResource[0].strip()]
    else:
        accountList = re.compile(pattern_act).findall(resp_act.read())
    if len(accountList) > 10000:
        print "The number of Account has exceed 10000, not supported yet!"
        sys.exit(1)

    for act in accountList:
        session = transferSession(act)
        contentSessionList.append(session)



    resp_act.close()
    print accountList
    print "#################act done#########################"

    #step2.2:swauth: list all the users'availabe in the system
    PB.setPhaseTime("User")
    userList = []
    userFullList = []
    pattern_usr = r'(?<="name": \").*?(?=\")'
    pattern_actid =  r'(?<="account_id": \").*?(?=\")'
    pattern_usrAuth = r'(?<="auth": "plaintext:).*?(?=\")'
    for ses in contentSessionList:
        orgIP = random.choice(orgIPL).strip()
        req_usr = urllib2.Request('http://%s/auth/v2/%s' % (orgIP,ses.getAccount()))
        req_usr.add_header('X-Auth-Admin-User', '.super_admin')
        req_usr.add_header('X-Auth-Admin-Key', 'rootroot')
        resp_usr = urllib2.urlopen(req_usr)
        PB.addUserSessionList(resp_usr)

        response = resp_usr.read()
        userList = re.compile(pattern_usr).findall(response)
        actid = re.compile(pattern_actid).findall(response)
        ses.addUserList(userList)
        actid = actid[0].replace("AUTH_","",1)
        ses.setAccountID(actid)
        ses.numACT += 1
        numAccount += ses.numACT

        newcontent += "%s:no:END" %(actid)+os.linesep
        tk = TokenFetch(orgIP)
        req_actMeta = urllib2.Request('http://%s/v1/%s' % (orgIP,"AUTH_"+actid))
        req_actMeta.add_header('x-auth-token',tk)
        req_actMeta.get_method = lambda: 'HEAD'
        resp_actMeta = urllib2.urlopen(req_actMeta)
        PB.addUserSessionList(resp_actMeta)

        if "X-Account-Meta-" in str( resp_actMeta.info()):
            metaDict = dict( resp_actMeta.info())
            for meta in metaDict:
                if "x-account-meta-" in meta :
                    value = resp_actMeta.info().getheader(meta)
                    ses.accountMeta[meta] = value
        resp_actMeta.close()

        if scopeResource == 'account':   #need act ID
            return '', contentSessionList


        userFullList += userList
        resp_usr.close()
        if len(userList) > 10000:
            print "The number of Users under account::%s has exceed 10000, not supported yet!" % (ses.getAccount())
            sys.exit(1)
        for usr in userList:
            orgIP = random.choice(orgIPL).strip()
            if specResource != "" and scopeResource == "":
                if usr == specResource[1].strip() or specResource[1].strip() == "":
                    req_usrP = urllib2.Request('http://%s/auth/v2/%s/%s' % (orgIP,ses.getAccount(),usr))
                else:
                    continue
            else:
                req_usrP = urllib2.Request('http://%s/auth/v2/%s/%s' % (orgIP,ses.getAccount(),usr))
            req_usrP.add_header('X-Auth-Admin-User', '.super_admin')
            req_usrP.add_header('X-Auth-Admin-Key', 'rootroot')
            resp_usrP = urllib2.urlopen(req_usrP)
            PB.addUserSessionList(resp_usrP)

            response = resp_usrP.read()
            userProp = {'name':'','auth':''}
            if '.reseller_admin' in response:
                userProp['name'] = '.reseller_admin'
            elif '.admin' in response:
                userProp['name'] = '.admin'

            auth =  re.compile(pattern_usrAuth).findall(response)
            userProp['auth'] = auth

            ses.addUserProperty(usr,userProp)
            actid = ses.getAccountID().replace("AUTH_","",1)
            ses.numUSR += 1
            newcontent += "%s-user@%s:no:END" % (actid,usr)+os.linesep
            resp_usrP.close()

        numUser += ses.numUSR
    print userFullList
    print "################user done##########################"

    #step2.2:swauth: get the superuser token

    token = ''
    orgIP = random.choice(orgIPL).strip()
    req_tk = urllib2.Request('http://%s/v1.0/' % (orgIP))
    req_tk.add_header('X-auth-user', '.super_admin')
    req_tk.add_header('X-auth-key', 'rootroot')
    resp_tk = urllib2.urlopen(req_tk)
    token = resp_tk.info().getheader('X-Auth-Token')
    resp_tk.close()

    print token
    print "################token done##########################"
    if scope == 'user':
        return token, contentSessionList
    #step3.1:swift: list all the containers availabe in the system
    PB.setPhaseTime("Container")
    containerList = []
    containerFullList = []

    for ses in contentSessionList:
        orgIP = random.choice(orgIPL).strip()

        if specResource != "" and scopeResource == "":
            url = "http://%s/v1/%s/%s" % (orgIP,"AUTH_"+ses.getAccountID(),specResource[2].strip())
        else:
            url = "http://%s/v1/%s" % (orgIP,"AUTH_"+ses.getAccountID())

        req_cont = urllib2.Request(url)
        req_cont.add_header('x-auth-token', token)

        try:
            resp_cont= urllib2.urlopen(req_cont)
        except urllib2.HTTPError as e:
            if e.code == 401:
                token = TokenFetch(orgIP)
                req_cont.add_header('x-auth-token', token)
                resp_cont= urllib2.urlopen(req_cont)
        except:
            print "container not exist maybe::%s-%s" % (ses.getAccountID(),cont)
            sys.exit(0)

        response = resp_cont.read()
        if specResource != "" and scopeResource == "" and specResource[2].strip() != "":
            containerList = [specResource[2].strip()]
        else:
            containerList = response.split()
        if len(containerList) > 10000:
            print "The number of Containers under account::%s has exceed 10000, not supported yet!" % (ses.getAccount())
            sys.exit(1)
        for cont in containerList:
            ses.containerMeta[cont] = {}
            ses.addContainer(cont)
            actid = ses.getAccountID().replace("AUTH_","",1)
            ses.numCONT += 1
            newcontent += "%s-%s:no:END" % (actid,cont)+os.linesep

            req_contMeta = urllib2.Request('http://%s/v1/%s/%s' % (orgIP,"AUTH_"+actid,cont))
            req_contMeta.add_header('x-auth-token',token)
            req_contMeta.get_method = lambda: 'HEAD'
            resp_contMeta = urllib2.urlopen(req_contMeta)
            PB.addContainerSessionList(resp_contMeta)

            objLength = int(resp_contMeta.info().getheader('x-container-object-count'))
            ses.SetObjectNumber(cont,objLength)
            if "X-Container-Meta-" in str( resp_contMeta.info()) or "X-Container-Read:" in str( resp_contMeta.info()) or "X-Container-Write:" in str( resp_contMeta.info()):
                metaDict = dict( resp_contMeta.info())
                for meta in metaDict:
                    if "x-container-meta-" in meta or "x-container-read" in meta or "x-container-write" in meta:
                        value = resp_contMeta.info().getheader(meta)
                        ses.containerMeta[cont][meta] = value




            resp_contMeta.close()

        containerFullList += containerList
        resp_cont.close()
        numContainer += ses.numCONT

    print containerFullList
    print "################container done##########################"
    if scope == 'container':
        return token, contentSessionList
    #step3.2.1:swift: list all the objects availabe in the system
    PB.setPhaseTime("Object")
    objectList = []
    objectFullList = []

    for ses in contentSessionList:
        for cont in ses.getContainer().keys():
            orgIP = random.choice(orgIPL).strip()
            if specResource != "" and scopeResource == "" and specResource[3].strip() != "":
                objLength = 1
            else:
                objLength = ses.GetObjectNumber(cont)

            print "%s object number ::::%s" % (cont,objLength)

            loopTime = objLength/10000 if (objLength%10000==0) else objLength/10000+1
            lastobj = ""
            for i in range(loopTime):
                while True:
                    print "Loop Time::",i
                    print "Time Tag::",time.strftime('%Y-%m-%d#%H:%M:%S', time.localtime(time.time()))

                    if specResource != "" and scopeResource == "" and specResource[3].strip() != "":
                        url = "http://%s/v1/%s/%s/%s" % (orgIP,"AUTH_"+ses.getAccountID(),cont,specResource[3].strip())
                    else:
                        url = "http://%s/v1/%s/%s?marker=%s" % (orgIP,"AUTH_"+ses.getAccountID(),cont,lastobj)

                    req_obj = urllib2.Request(url)
                    req_obj.add_header('x-auth-token', token)

                    try:
                        resp_obj= urllib2.urlopen(req_obj)
                        PB.addObjectSessionList(resp_obj)
                    except urllib2.HTTPError as e:
                        if e.code == 401:
                            token = TokenFetch(orgIP)
                            req_obj.add_header('x-auth-token', token)
                            resp_obj= urllib2.urlopen(req_obj)
                            continue
                    try:
                        response = resp_obj.read()
                    except:
                        continue
                    objectList = response.split()
                    lastobj = objectList[-1]

                    ses.addObjList(cont, objectList)
                    objectFullList += objectList
                    resp_obj.close()
                    break

            objectDict = ses.getContainer()[cont]["objFullDict"]
            actid = ses.getAccountID().replace("AUTH_","",1)

            ses.numOBJ += len(objectDict)
        numObject += ses.numOBJ
    print "################object done##########################"
    #step3.2.2:swift: list all the objects MD5 value availabe in the system
    PB.setPhaseTime("MD5")
    newcontent = newcontent.replace("MD5##","")
    for ses in contentSessionList:
        for cont in ses.getContainer().keys():
            print "@@@@@@%s-%s's length@@@@@" % (ses.getAccountID(),cont)
            print len(ses.getContainer()[cont]["objFullDict"])


            if 100 > ses.GetObjectNumber(cont):
                m = {}
                n = {}
                for obj in ses.getContainer()[cont]["objFullDict"]:
                    m[obj] = []
                    n[obj] = []
                    md5Fetch(m,n,orgIPL,linuxRecIP,ses,cont,obj,token)
            elif 1000 > ses.GetObjectNumber(cont):
                md5_jobs = []
                idx = 0
                manager = Manager()
                m = manager.dict()
                n = manager.dict()

                for obj in ses.getContainer()[cont]["objFullDict"]:
                    if obj == "objNum":
                        continue
                    m[obj] = []
                    n[obj] = []
                    p = Process(target=md5Fetch, args=(m,n,orgIPL,linuxRecIP,ses,cont,obj,token))
 
                    p.start()
                    md5_jobs.append(p)
                    PB.addMD5SessionList(p)
                    if idx%500 == 0:
                        time.sleep(2)

                    idx = idx + 1
                for i in md5_jobs:
                    i.join()

            else:
                manager_obj = Manager()
                md5numDict = manager_obj.dict()
                for ip in orgIPL:
                    md5numDict[ip] = configure["md5Process"]
                step = configure["md5Loop"]
                #auto change the steps for each container
                tuningDict = autoTuning("md5",ses,orgIPL)
                step = int(tuningDict[cont]["md5Loop"])
                md5_jobs = []
                idx = 0
                manager = Manager()
                m = manager.dict()
                n = manager.dict()
                manager2 = Manager()
                md5Dict = manager2.dict()
                md5Dict["token"] = token

                loopTime = int(ses.GetObjectNumber(cont))/step if (int(ses.GetObjectNumber(cont))%step==0) else int(ses.GetObjectNumber(cont))/step+1
                print configure["md5Loop"]
                print configure["md5Process"]
                for x in range(loopTime):
                    while True:
                        orgIP = random.choice(orgIPL).strip()
#                       print "Debug:ZYJ::MD5::",md5numDict[orgIP]
                        orgCheck = md5numDict[orgIP] - 1
                        if orgCheck >= 1:
                            md5numDict[orgIP] -= 1
                            token = md5Dict["token"]
                            p = Process(target=md5FetchBatch, args=(m,n,md5Dict,md5numDict,orgIP,linuxRecIP,ses,cont,token,idx,step))
                            p.start()
                            md5_jobs.append(p)
                            PB.addMD5SessionList(p)

                            idx = idx + 1
                            break
                        else:
                            continue


                for i in md5_jobs:
                    i.join()


            ses.container[cont]["objFullDict"] = dict(m)
            metaDict = dict(n)
            
            for obj in metaDict:
                for metaGroup in metaDict[obj]:
                    name  = metaGroup.split('::')[0]
                    value = metaGroup.split('::')[1]
                    ses.objectMeta[cont][obj][name] = value


    print "################md5 done##########################"
    print contentSessionList
    print "Time Tag::",time.strftime('%Y-%m-%d#%H:%M:%S', time.localtime(time.time()))
#   sys.exit(1)
    return token, contentSessionList
    

def md5FetchBatch(m,n,md5Dict,md5numDict,orgIP,linuxRecIP,session,container,token,idx,step):
    list = session.getContainer()[container]["objFullDict"].keys()[idx*step:(idx+1)*step]
    for obj in list:
        m[obj] = []
        n[obj] = []
        orgIPL = [orgIP]
        while True:
            try:
                md5Fetch(m,n,orgIPL,linuxRecIP,session,container,obj,token)
                break
            except:
                continue
    md5numDict[orgIP] += 1



def md5Fetch(m,n,orgIPL,linuxRecIP,session,container,object,token):
    ipR = random.choice(linuxRecIP.keys())
    devR = linuxRecIP[ipR]

    handler = BoundHTTPHandler(source_address=(ipR, 0, devR))
    openerR = urllib2.build_opener(handler)
    while True:
        try:
            md5 = ""
            ip = random.choice(orgIPL).strip()
            url = "http://%s/v1/%s/%s/%s" % (ip,"AUTH_"+session.getAccountID(),container,object)
            req_md5 = urllib2.Request(url)
            req_md5.add_header('x-auth-token', token)
            req_md5.get_method = lambda: 'HEAD'

            while True:
                try:
                    resp_md5 = openerR.open(req_md5,None,10000)
                    break
                except urllib2.HTTPError as e:
                    if e.code == 401:
                        token = TokenFetch(ip)
                        md5Dict["token"] = token
                        req_md5.add_header('x-auth-token', token)
                        resp_md5= urllib2.urlopen(req_md5)
                        break
                except:
                    e = sys.exc_info()[0]
                    print "<p>Error: %s</p>" % e
                    print traceback.print_exc()
                    continue

            md5 = resp_md5.info().getheader('ETag').replace('"','')
            length = resp_md5.info().getheader('Content-Length')

            m[object] = [md5,length]

            if "X-Object-Meta-" in str( resp_md5.info()) or "X-Object-Read:" in str( resp_md5.info()) or "X-Object-Write:" in str( resp_md5.info()):
                metaDict = dict( resp_md5.info())
                for meta in metaDict:
                    if "x-object-meta-" in meta or "x-object-read" in meta or "x-object-write" in meta :
                        value = resp_md5.info().getheader(meta)
                        n[object] += [str(meta)+"::"+str(value)]

            break
        except:
            e = sys.exc_info()[0]
            print "<p>Error: %s</p>" % e
            print traceback.print_exc()
            continue

    resp_md5.close()
    return md5


if __name__ == '__main__':
    usage ="""
example: %prog -o "192.168.24.210,192.168.24.211...." -d "192.168.24.218,192.168.24.219....." [-r <all | account | user | container> | -s <account::user::container::object>]
"""
    parser = optparse.OptionParser(usage)

    parser.add_option("-o", "--OriginaCDE", dest="orgIP",
                      default='Null',action="store",
                      help="the Source IP address group from CDE machine")
    parser.add_option("-d", "--DestinayColusa", dest="destIP",
                      default='Null',action="store",
                      help="the Destinay IP address group from Colusa machine")
    parser.add_option("-r", "--Range", dest="scope",
                      default='Null',action="store",
                      help="the scope of contents specify by the user: all/account/container/user")
    parser.add_option("-s", "--Special", dest="specResource",
                      default='Null',action="store",
                      help="the contents specify by the user: account::user::container::object")

    (options, args) = parser.parse_args()

    argc = len(args)
    if argc != 0:
        parser.error("incorrect number of arguments")
        print (usage)
    else:
        if options.orgIP != "Null" and options.destIP != "Null":
            if options.scope == "Null" and options.specResource == "Null": 
               options.scope =  raw_input("Please specify the range of resource needed to transfer: account/user/container/all? \n")
               sys.exit(1)
            if options.specResource == "Null": 
                if options.scope.strip().lower() not in ["account","user","container","all"]:
                    print "execution stop for empty scope/specified option"
                    sys.exit(1)
                else:
                    cRange = options.scope.strip().lower()
                    cSpec = ""
            else:
                cSpec =  options.specResource.strip().lower()
                cRange = ""

            oIPL = options.orgIP.split(",")
            dIPL = options.destIP.split(",")

            oipadd = oIPL[0].strip()
            mask = '255.255.252.0'         
            anded = list()
            for ip, m in zip(oipadd.split('.'),mask.split('.')):
                      anded.append(str(int(ip) & int(m)))

            orgsubnet = '.'.join(anded)

            dipadd = dIPL[0].strip()
            mask = '255.255.252.0'         
            anded = list()
            for ip, m in zip(dipadd.split('.'),mask.split('.')):
                      anded.append(str(int(ip) & int(m)))

            destsubnet = '.'.join(anded)

            orgPortL = os.popen("route -n | awk '/%s/{print$NF}'" % (orgsubnet)).read().split()
            destPortL = os.popen("route -n | awk '/%s/{print$NF}'" % (destsubnet)).read().split()

            global configure
            global records
            global oldcontent
            global newcontent
            global numAccount,numUser,numContainer,numObject
            numAccount=numUser=numContainer=numObject=0
            records = ""
            configure = {}
            configure["md5Process"] = 20
            configure["md5Loop"] = 100
            configure["objProcess"] = 20
            configure["objLoop"] = 100
            configure["netmaskORG"] = "255.255.255.0"
            configure["netmaskDST"] = "255.255.255.0"

            try:
                with open("configure.conf") as f:
                    data = f.read()
                    for i in data.split("\n") :
                        if "md5 Process" in i:
                            configure["md5Process"] = int(i.split(":")[1].strip())

                        if "md5 Loop" in i:
                            configure["md5Loop"] = int(i.split(":")[1].strip())

                        if "object Process" in i:
                            configure["objProcess"] = int(i.split(":")[1].strip())

                        if "object Loop" in i:
                            configure["objLoop"] = int(i.split(":")[1].strip())

                        if "netmask ORG" in i:
                            configure["netmaskORG"] = i.split(":")[1].strip()

                        if "netmask DST" in i:
                            configure["netmaskDST"] = i.split(":")[1].strip()
                    
            except:
                print "no configure file specified, setting with the default"


            logDir = os.popen('ls -dtr XsferLogDir_* | tail -n 1').read().strip()
            timeTag = time.strftime('%Y-%m-%d#%H:%M:%S', time.localtime(time.time()))
            workingDir = os.getcwd()
            newLogDir = "XsferLogDir_%s"%(timeTag)
            os.mkdir(newLogDir)


            if logDir != "":
                os.chdir(logDir)
                os.popen("grep -h yes Xsfer.log_* | sort | uniq > Xsfer.log")
                name  = "Xsfer.log"
                file = open(name, 'r')
                oldcontent = file.read()
                file.close()
                os.chdir(workingDir)
            else:
                oldcontent = ""

            newcontent=""
            os.chdir(newLogDir)

            timeTag = time.strftime('%Y-%m-%d#%H:%M:%S', time.localtime(time.time()))
            milliTag = datetime.datetime.now().microsecond
            file = open('Xsfer.log_old_%s_%s' % (timeTag,milliTag), 'w+')
            file.write(oldcontent)
            file.close()


            global objDict
            global orgIPL
            global destIPL
            global pidDict
            pidDict = {}
            objDict = {}
            orgIPL = oIPL
            destIPL = dIPL
            try:
                pidDict["Main"] = os.getpid()
                print "Main Session PID == ",pidDict
                result = Execute(cRange,cSpec,orgPortL,destPortL)
            except KeyboardInterrupt:
                print("Auto Stop has been Detected")
                timeTag = time.strftime('%Y-%m-%d#%H:%M:%S', time.localtime(time.time()))
                milliTag = datetime.datetime.now().microsecond
                file = open('Xsfer.log_%s_%s' % (timeTag,milliTag), 'w+')
                file.write(newcontent)
                file.close()
                os.popen("killall python")
                sys.exit(0)

        else:
            print (usage)
            sys.exit(1)


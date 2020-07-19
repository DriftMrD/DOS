## -*- coding: utf-8 -*- 
import errno
import socket
import time
import random
import hmac
import time
import signal

from Crypto.Cipher import AES
from hashlib import sha256

class mycrypt():
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CBC

    def mydecrypt(self, text):
        cryptor = AES.new(self.key, self.mode, "BBBBBBBBBBBBBBBB")
        plain_text = cryptor.decrypt(text)
        return plain_text

class TimeOutException(Exception): pass
def outOfTime(num):
    def wrape(func):
	def timeOutHandle(signum, frame):
            raise TimeOutException("This Packet is missing")
	def toDo(*args, **kwargs):
	    try:
                signal.signal(signal.SIGALRM, timeOutHandle)
                signal.alarm(num)
                retValue = func(*args, **kwargs)
                signal.alarm(0)
                return retValue
            except TimeOutException:
                return '-1'
        return toDo
    return wrape

if __name__ == '__main__':


    @outOfTime(1)
    def recvMessage():
        total_data=[];recvData=''
        while True:
            recvData=xvs_sock.recv(8192)
            if endTag in recvData:
                total_data.append(recvData[:recvData.find(endTag)])
                break
            total_data.append(recvData)
            if len(total_data)>1:
                # check if end_of_data was split
                last_pair=total_data[-2]+total_data[-1]
                if endTag in last_pair:
                    total_data[-2]=last_pair[:last_pair.find(endTag)]
                    total_data.pop()
                    break
        # print ('Receiving Complement')
        recvMessage = ''.join(total_data)
        return recvMessage

    def reStart():
        reStaMsg = 'RESTART,'+str(counterd) +endTag
        print(reStaMsg)
        xvs_sock.send(reStaMsg)
        return

    @outOfTime(5)
    def buildConnect():
        xvs_sock.connect((server_ip, server_port))
        # print 'connected\n\n'
        # send Message 1
        return 'Connected'

        
    
    # set server address and port
    stateArr = [0,0,0,0,0,0,0,0,0,0]# to record the recent 10 times results of message communication
    startTime = time.time()
    server_ip = "192.168.1.100"
    server_port = 6632

    SDF_HELLO_D = 'hello_d'
    FEATURE_REPLY = 'fearture_reply'
    MASTERKEY = 'AAAABBBBCCCCDDDD'
    endTag = 'MARKER'
    nu = 0
    re = 0
    start = 1
    counterd = 1
    lossCounter = 0
    numLossTen = 0
    numFileLoss = 0
    numSocket = 0
    outputInfo = ''
    extraInfo = ''
    recFile = open("/home/pi/Desktop/device_communication_attacked_sp2w_bs.csv", "a")

    print 'Begin'

    # generate random number ND
    nonceND = random.randint(10000000, 999999999)
    # print "nonceND", nonceND

    # print start title
    # print ("Times(S&L)\tRunnig-Time\tAverage-Time\tTotal-Time\tTotal-ExeTime\tMsg-trans-Time\t\tLP\tTLP\n")
    recFile.write("Times(S&L)\tRunnig-Time\tAverage-Time\tTotal-Time\tTotal-ExeTime\tMsg-trans-Time\t\tLP\tTLP\n")
    
    # Generate Message1
    D_ID = '00000002'
    # msg1 = (SDF_hellod,ND,D)
    msg1 = SDF_HELLO_D + ','+ str(nonceND) + ',' + D_ID +endTag
    # print 'msg1:', msg1

    try:
        while True:
            start = 1
            nu = 0 # prepare for the next times message communication.
            lastEndTime = time.time()
            exeStartTime = time.clock()
            try:
                # connect the server
                xvs_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # xvs_sock.setblocking(1)
                # print 'begin to connect'
                if buildConnect() != 'Connected':
                    print 'Overtime'
                    raise socket.error
            except socket.error:
                signal.alarm(0)
                print 'Socket Connecting Error'
                numSocket += 1
                start = 0
            if(re == 1):
                reStart()
                re = 0
            if (start == 1): xvs_sock.send(msg1)
            
            while start == 1:
                try:
                    data = recvMessage()
                    # buf_len = len(data)
                    # print data
                    # print "buf_len:", buf_len
                    # print 'nu:', nu
                except socket.error:
                    signal.alarm(0)
                    data = '-1'
                if data == '-1':
                    print "\ndisconnected\n"
                    time.sleep(1)
                    break
                else:
                    if nu == 1:
                        try:
                            # receive msg3
                            FEATURE_REQUEST = data.split(',')[0]
                            macC = data.split(',')[1]
                            # print 'macC:', macC
                        except IndexError:
                            print "Receive Wrong informtion or Msg 3"
                            break

                        # calculate MacC by itself
                        hmachString = SDF_HELLO_D + str(nonceND) + D_ID + SDF_HELLO_C + nonceNC + C_ID + FEATURE_REQUEST
                        hmach = hmac.new(MASTERKEY, '', sha256)
                        hmach.update(hmachString)
                        macC_D = hmach.hexdigest()
                        # print 'macC_D:', macC_D

                        # calculate macD
                        if (macC == macC_D):
                            hmachString = SDF_HELLO_D + str(nonceND) + D_ID + SDF_HELLO_C + nonceNC + C_ID + FEATURE_REQUEST + FEATURE_REPLY
                            hmach = hmac.new(MASTERKEY, '', sha256)
                            hmach.update(hmachString)
                            macD = hmach.hexdigest()
                            # print 'macD:', macD

                            # calculate K
                            kString = nonceNC + str(nonceND)
                            hmach = hmac.new(MASTERKEY, '', sha256)
                            hmach.update(kString)
                            K = hmach.hexdigest()
                            # print 'K:', K

                            # send msg4
                            # mgs4 = (FEATURE_REPLY,macD)
                            msg4 = FEATURE_REPLY +','+ macD + endTag
                            # print 'msg4:', msg4

                            xvs_sock.send(msg4)
                            nu = 2
                        else:
                            print '\nConnected err MAC-code for message cannot match\n'
                            break
                        
                    elif nu == 0:
                        # print ('This is the %d times message receive to Arduion Recode'%counterd )
                        # receive msg2
                        try:
                            SDF_HELLO_C = data.split(',')[0]
                            nonceNC = data.split(',')[1]
                            C_ID = data.split(',')[2]
                        except IndexError:# if the program get this except means it get the wrong message 2
                            print 'The unmatching information for receive message 2!'
                            break             
                        nu = 1
                        # print 'msg2:', data
                    else:
                        cipherContent = data[:12528] # the cipher hex code size, should change if file 
                        macC_hex = data[12528:]
                        # print 'cipherContent', cipherContent
                        # print 'macC_hex:', macC_hex

                        # calculate MacD_hex
                        hmachString = cipherContent # + str(counterd)
                        # print('counterd='+str(counterd))
                        hmach = hmac.new(K, '', sha256)
                        hmach.update(hmachString)
                        macD_hex = hmach.hexdigest()
                        # print 'macD_hex:', macD_hex

                        if (macC_hex == macD_hex):
                            # print "hex code mathched!"
                            en = mycrypt(K[0:32])
                            deciperContent = en.mydecrypt(cipherContent).rstrip('@')
                            # print 'decipherContent:', deciperContent
                            receivedata = open('received.hex', 'w')
                            receivedata.write(deciperContent)
                            # print 'hex file received.'
                            receivedata.close()
                            nu = 3
                            break
                        else:
                            print 'Connected err: MAC-code for hex file cannot match'
                            break

            arrNum = (counterd + lossCounter)%10
	    endTime = time.time()
	    exeEndTime = time.clock()
	    rTime = endTime-lastEndTime # the using time for this communication 
            exeRTime = exeEndTime-exeStartTime
            msgTime = rTime - exeRTime
	    avrTime = (endTime-startTime-(counterd+lossCounter-1))/((counterd+lossCounter)) # the average time 
	    totTime = endTime-startTime# the total time for the message communication  
	    totExeTime = totTime-(counterd+lossCounter-1)# the total time except program sleeping time
            counterd += 1
            if (nu != 3):
                print 'err'
                lossCounter += 1
                counterd -= 1
                if(stateArr[arrNum] != 1):
                    stateArr[arrNum] = 1
                    numLossTen += 1
            else:
                 if(stateArr[arrNum] != 0):
                    stateArr[arrNum] = 0
                    numLossTen -= 1
            if (nu == 2):
                # re = 1
                numFileLoss += 1
            lossPer = (numLossTen-1)*(0.1)+0.1
            totLossPer = float(lossCounter)/(counterd+lossCounter-1)
            # Get Information
            counterInfo = str(counterd-1)+'&'+str(lossCounter)
            timeInfo = str(rTime)+'\t'+str(avrTime)+'\t'+str(totExeTime)+'\t'+str(totTime)+'\t'+str(msgTime)
            extraInfo = str(lossPer)+'\t'+str(totLossPer)
            outputInfo = counterInfo+'\t\t'+timeInfo + '\t\t'+extraInfo 
            if start == 0:
                outputInfo = counterInfo + '\t\t' + 'Socket Error-Null Information'
            # print(outputInfo)
            recFile.write (outputInfo+'\n')
            if(start == 1):
                xvs_sock.close()
            
            # make sure the next message communication happen after at least 5 second.
            time.sleep(1)
            # print 'over\n\n'

    except KeyboardInterrupt or socket.error:
        # io_loop.stop()
        xvs_sock.close()
        numLoss = 0
        for item in stateArr:
            if item == 1: 
                numLoss += 1
        finalInfo = 'Total-Times:' + str(lossCounter+counterd-1) + '\t' + 'Loss-Times:' + str(lossCounter) + '\t' + 'Recent 10 times loss possiblity: 0.' + str(numLoss) + '\t' + 'Total Hex File Loss number: ' + str(numFileLoss) + '\t' + 'Socket disconnectable number: ' + str(numSocket)
        # print(finalInfo)
        recFile.write('\n'+finalInfo + '\n')
        recFile.close()
        print '>>>quit'

        exit(0)

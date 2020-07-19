### -*- coding: utf-8 -*- 
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
            except TimeOutException, e:
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
                #check if end_of_data was split
                last_pair=total_data[-2]+total_data[-1]
                if endTag in last_pair:
                    total_data[-2]=last_pair[:last_pair.find(endTag)]
                    total_data.pop()
                    break
        #print ('Receiving Complement')
        recvMessage = ''.join(total_data)
        return recvMessage
    
    def reStart():
        def sendRS():
            msgRS = 'RESTART,'+str(counterd) + endTag
            print msgRS
            xvs_sock.send(msgRS)
            msgWro = ''
            while((msgWro != 'RESTART')and(msgWro != '-1')):
                # print(msgWro)
                print('...')
                msgWro = recvMessage()
            if(msgWro == '-1'):
                print 'Restarted-Packet Loss.\nStart to resend this command.'
                sendRS()
            return 
        
        print('Running Time: %s'%errTime)
        print('Runing Times: <Successed: %d; Failed: %d>'%(counterd, lossCounter))
        arrNum = (counterd + lossCounter)%10 
        stateArr[arrNum] = 1
        numLoss = 0
        for item in stateArr:
            if item == 1:
                numLoss += 1

        print('Total Packet Loss Probability:%s'%(float(lossCounter)/(counterd + lossCounter)))
        print('Packet Loss Probability: 0.%d'%numLoss)
        print('Start to reset the connection...')       
        sendRS()
        print 'Start!\n\n'
    
    
    #set server address and port
    stateArr = [0,0,0,0,0,0,0,0,0,0]# to record the recent 4 times results of message communication
    startTime = time.time()
    lastEndTime = startTime
    server_ip = "192.168.1.103"
    server_port = 6632

    SDF_HELLO_D = 'hello_d'
    FEATURE_REPLY = 'fearture_reply'
    MASTERKEY = 'AAAABBBBCCCCDDDD'
    endTag = 'MARKER'
    counterd = 1
    lossCounter = 0 

    print 'Begin'

    # generate random number ND
    nonceND = random.randint(10000000, 999999999)
    #print "nonceND", nonceND

    #connect the server
    xvs_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #xvs_sock.setblocking(1)
    print 'begin to connect'
    xvs_sock.connect((server_ip, server_port))
    nu = 0

    # Generate Message1
    print 'connected\n\n'
    D_ID = '00000002'

    # print start title
    print 'Times\tRunnig-Time\tAverage-Time\tTotal-Time\tTotal-Exe-Time '

    #msg1 = (SDF_hellod,ND,D)
    msg1 = SDF_HELLO_D + ','+ str(nonceND) + ',' + D_ID +endTag
    #print 'msg1:', msg1

    try:
        while True:
	    #send Message 1
            xvs_sock.send(msg1)
            
            while 1:
	        data = ''
                data = recvMessage()
                buf_len = len(data)
                #print data
                #print "buf_len:", buf_len
                #print 'nu:', nu

                if data == '':
                    #print "disconnected"
                    #xvs_sock.close()
                    #continue
                    pass
	        elif data == '-1':
                    print 'Packet Loss!'
                    endTime = time.time()
                    lossCounter += 1
                    errTime = endTime-lastEndTime
                    startTime -= errTime
                    lastEndTime = endTime
                    reStart()
                    nu = 0
                    break
                
                else:
                    if nu == 1:
                        #receive msg3
                        FEATURE_REQUEST = data.split(',')[0]
                        macC = data.split(',')[1]
                        #print 'macC:', macC

                        #calculate MacC by itself
                        hmachString = SDF_HELLO_D + str(nonceND) + D_ID + SDF_HELLO_C + nonceNC + C_ID + FEATURE_REQUEST
                        hmach = hmac.new(MASTERKEY, '', sha256)
                        hmach.update(hmachString)
                        macC_D = hmach.hexdigest()
                        #print 'macC_D:', macC_D

                        # calculate macD
                        if (macC == macC_D):
                            hmachString = SDF_HELLO_D + str(nonceND) + D_ID + SDF_HELLO_C + nonceNC + C_ID + FEATURE_REQUEST + FEATURE_REPLY
                            hmach = hmac.new(MASTERKEY, '', sha256)
                            hmach.update(hmachString)
                            macD = hmach.hexdigest()
                            #print 'macD:', macD

                            #calculate K
                            kString = nonceNC + str(nonceND)
                            hmach = hmac.new(MASTERKEY, '', sha256)
                            hmach.update(kString)
                            K = hmach.hexdigest()
                            #print 'K:', K

                            # send msg4
                            #mgs4 = (FEATURE_REPLY,macD)
                            msg4 = FEATURE_REPLY +','+ macD + endTag
                            #print 'msg4:', msg4

                            xvs_sock.send(msg4)
                            nu = 2
                            #xvs_sock.close()
                            continue
                        else:
                            print 'Connected err MAC-code for message cannot match'
                            endTime = time.time()
                            lossCounter += 1
                            errTime = endTime-lastEndTime
                            startTime -= errTime
                            lastEndTime = endTime
                            reStart()
                            nu = 0
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
                            endTime = time.time()
                            lossCounter += 1
                            errTime = endTime-lastEndTime
                            startTime -= errTime
                            lastEndTime = endTime
                            reStart() 
                            nu = 0
                            break
                        
                        nu = 1
                        #print 'msg2:', data
                    else:
                        cipherContent = data[:12528] # the cipher hex code size, should change if file 
                        macC_hex = data[12528:]
                        # print 'cipherContent', cipherContent
                        # print 'macC_hex:', macC_hex

                        #calculate MacD_hex
                        hmachString = cipherContent + str(counterd)
                        hmach = hmac.new(K, '', sha256)
                        hmach.update(hmachString)
                        macD_hex = hmach.hexdigest()
                        #print 'macD_hex:', macD_hex

                        if (macC_hex == macD_hex):
                            #print "hex code mathched!"
                            en = mycrypt(K[0:32])
                            deciperContent = en.mydecrypt(cipherContent).rstrip('@')
                            #print 'decipherContent:', deciperContent
                            receivedata = open('received.hex', 'w')
                            receivedata.write(deciperContent)
                            #print 'hex file received.'
                            receivedata.close()
                        else:
                            print 'Connected err MAC-code for hex file cannot match'
                            lossCounter += 1
                            errTime = endTime-lastEndTime
                            startTime -= errTime
                            lastEndTime = endTime
                            reStart()
                            nu = 0
                            break
                        nu = 0 # prepare for the next times message communication.
                        arrNum = (counterd + lossCounter)%5 
                        stateArr[arrNum] = 0
		        endTime = time.time()
		        rTime = endTime-lastEndTime # the using time for this communication 
		        avrTime = (endTime-startTime-counterd+1)/(counterd) # the average time 
		        totTime = endTime-startTime# the total time for the message communication  
		        totExeTime = totTime-counterd+1# the total time except program sleeping time
		        # print('Running Time: %s Seconds'%rTime)
		        # print('Average Running time: %s Seconds'%avrTime)
		        outputInfo = str(counterd)+'\t'+str(rTime)+'\t'+str(avrTime)+'\t'+str(totTime)+'\t'+str(totExeTime)
		        print (outputInfo)
		        time.sleep(1) # make sure the next message communication happen after at least 5 second.
                        lastEndTime = time.time() # record the time
                        counterd += 1
                        #print 'over\n\n'
                        break

    except KeyboardInterrupt:
        #io_loop.stop()
        print ">>>quit"

        sys.exit(0)

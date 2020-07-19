### -*- coding: utf-8 -*- 
import socket
import time
import random
import hmac
import sys
import binascii
import signal

from Crypto.Cipher import AES
from hashlib import sha256
from time import clock

class mycrypt():
    def __init__(self,key):
        self.key = key
        self.mode = AES.MODE_CBC
         
    def myencrypt(self,text):
        cryptor = AES.new(self.key,self.mode, 'BBBBBBBBBBBBBBBB') #key, mode ,vi
        length = 16
        count = text.count('')
        #print 'count:', count
        if count < length:
            add = (length-count) + 1
            text = text + ('@' * add)
        elif count > length:
            add = (length-(count % length)) + 1
            #print "add:", add
            text = text + ('@' * add)
        self.ciphertext = cryptor.encrypt(text)
        return self.ciphertext
        
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
					

if __name__== '__main__':

    @outOfTime(1)
    def recvMessage():
        total_data=[];recvData=''
        while True:
            recvData=connection.recv(1024)
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

    #constant value
    endTag = 'MARKER'
    HOST = '192.168.1.110'
    PORT = 6632
    C_ID = '00000001'
    SDF_HELLO_C = 'hello_c'
    FEATURE_REQUEST = 'feature_request'
    MASTERKEY = 'AAAABBBBCCCCDDDD'
    nu = 0
    counter = 1
    lossCounter = 0

    print('Begin')
    startTime = time.time()# set Start Time

    try:
        while True:
        
            #TCP link
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s. setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
            #s.setblocking(1) #blocking model
            s.bind((HOST,PORT))
            print('Listen to connecting...\nThis is %d times connection building and loss %d packets'%(counter, lossCounter))

            s.listen(5)
            connection,address = s.accept()
            print ('connect with Device'+str(address))
    
            # Record the time for the Communication
            lastEndTime = time.time()

            # while receiving M1
            #print('Connected. Got connection from ',address)
            #print('%s:%s connect' %client_addr) 
            while 1:
                #receive message for the client 
                clientStr = recvMessage()
                length = len(clientStr)
                
                if('RESTART' in clientStr):
                    print clientStr
                    counter = int(clientStr.split(',')[1])
                    print ('Recorrect, this is the %d times connection'%counter)
                    continue
                    
                #print("message length: %d" %length)
                #print("message from client: " + clientStr)
                if(length == '-1'): 
                    print 'Error: Message Loss'
                    
                if nu == 1:
                    #receive msg4
                    #print 'receive msg4'
                    try:
                        FEATURE_REPLY = clientStr.split(',')[0]
                        macD = clientStr.split(',')[1]
                    except IndexError: 
                        print'Receive Error in msg4.'
                        break
                    # calculate macD by itself
                    hmacString = SDF_HELLO_D + nonceND + D_ID + SDF_HELLO_C + str(nonceNC) + C_ID + FEATURE_REQUEST + FEATURE_REPLY
                    hmach = hmac.new(MASTERKEY,'',sha256)
                    hmach.update(hmacString)
                    macD_C = hmach.hexdigest()
                    #print 'macD_C:', macD_C 

                    if ( macD_C == macD ):
                        #print "macD is matched"
                        #calculate K
                        kString = str(nonceNC) + str(nonceND)
                        hmach = hmac.new(MASTERKEY,'',sha256)
                        hmach.update(kString)
                        K = hmach.hexdigest()
                        #print K
                        #print 'K:', K, K[0:32]
                        
                        nu = 2

                        #read 
                        fh = open(r'Blink.hex', 'rb')
                        content = fh.read()
                        fh.close()
                        #print 'content length:', len(content)
                        #hexstr = binascii.b2a_hex(content)
                        #bsstr = bin(int(hexstr,16))[2:]
                        #print 'bin: ',bsstr, type(bsstr) 
                        #print 'content:', content
                        en = mycrypt(K[0:32]) #key must be 16 24 or 32 bytes
                        cipherContent = en.myencrypt(content)
                        #print 'cipherContent:', cipherContent
                        #print 'cipherContent_length', len(cipherContent)

                        #compute HEX file macC 
                        hmacString = cipherContent # + str(counter)
                        print ('counter='+str(counter))
                        hmach = hmac.new(K,'',sha256)
                        hmach.update(hmacString)
                        macC_hex = hmach.hexdigest()
                        #print 'macC_hex:', macC_hex
                        connection.send(cipherContent + macC_hex+ endTag)

                        """FILEINFO_SIZE=struct.calcsize('128s32sI8s')
                        BUFSIZE = 1024  
                        fhead=struct.pack('128s11I',filename,0,0,0,0,0,0,0,0,os.stat(filename).st_size,0,0)
                        connection.send(fhead)
                        while 1:
                            filedata = fp.read(BUFSIZE)
                            if not filedata: break
                            sendSock.send(filedata)"""

                        #print "sending file finished"
                        break    
                    else: 
                        print'Match Error in Msg4'
                        break
                #4 receive M1
                elif nu == 0:
	            # Server side
                    #generate random number NC
                    #print "random number NC"
                    nonceNC = random.randint(10000000,999999999)
                    #print 'nonceNC:', nonceNC

                    #. Send msg2 to Client(D)
                    msg2 = SDF_HELLO_C + ',' + str(nonceNC) + ',' + C_ID + endTag
                    #print 'msg2:', msg2
                    connection.send(msg2)

                    #receive msg1
                    try:
                        SDF_HELLO_D = clientStr.split(',')[0]
                        nonceND = clientStr.split(',')[1]
                        D_ID= clientStr.split(',')[2]
                    except IndexError:
                        print'Receive Error in Msg1!'
                        break
                         
                    # calculate macC
                    hmacString = SDF_HELLO_D + nonceND + D_ID + SDF_HELLO_C + str(nonceNC) + C_ID + FEATURE_REQUEST
                    hmach = hmac.new(MASTERKEY,'',sha256)
                    hmach.update(hmacString)
                    macC = hmach.hexdigest()
                    #print 'macC:', macC

	            #. Send msg3 to Client(D)
                    msg3 = FEATURE_REQUEST + ',' + macC + endTag
                    time.sleep(0.1)
                    connection.send(msg3)
                    nu = 1
                    #print 'msg3 nu:', nu
                    continue
                else:
                    #print 'End'
                    pass
                    
            endTime = time.time()
            print('Runing Time: %s'%(endTime-lastEndTime))
            print('Average Running Time: %s Seconds'%((endTime-startTime-counter+1)/counter))
            print('Total Runing Time: %s'%(endTime-startTime-counter+1))
            print('Run Times: %d Times' %counter)
            if(nu != 2): 
                lossCounter += 1
                counter -= 1
            nu = 0
            counter += 1 #counter +1
            time.sleep(1)
            lastEndTime = time.time()
            print 'over \n\n'
            s.shutdown(2)
    except KeyboardInterrupt:
        s.close()
        print 'KeyboardInterrupt'
        sys.exit(0)
        

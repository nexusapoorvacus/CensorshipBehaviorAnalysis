import threading, sys, os, time, signal, pickle
from scapy.all import *
from random import randint


# STATUS CODES
NO_RESPONSE_SYNACK = -1 #!
NO_RESPONSE_ACK_1 = -2  #@
NO_RESPONSE_ACK_2 = -3  ##
NO_HTTP_RESPONSE = -4   #$
RECEIVED_RESPONSE = 1   #%
RECEIVED_HTTP_RESPONSE = 2 # correct response, not a status code message
RECEIVED_HTTP_STATUS_MSG = 3 #^

# SNIFFER VARIABLES
receivedHTTPResponse = False

def send_packet_fragmented(ip, req):
  global receivedHTTPResponse
  firstPartLen = req.index("Host:")
  ip = IP(dst=ip)	
  # Generate random source port number
  port = randint(2000, 60000)
  # Create SYN packet
  SYN=ip/TCP(sport=port, dport=80, flags="S", seq=42)
  # Send SYN and receive SYN,ACK
  print ("Sending SYN packet")
  SYNACK=sr1(SYN, timeout=5)
  print ("Receiving SYN,ACK packet")
  # could not establish connection with destination
  if SYNACK == None:
    print ("Did not receive SYNACK")
    return NO_RESPONSE_SYNACK
  # Create ACK packet
  ACK = ip/TCP(sport=SYNACK.dport, dport=80, flags="A", seq=SYNACK.ack, ack=SYNACK.seq+1)
  reply0 = sr1(ACK, timeout=3)
  ACK=ip/TCP(sport=SYNACK.dport, dport=80, flags="A", seq=SYNACK.ack, ack=SYNACK.seq+1) / (req[:firstPartLen] + "\r\n")
  receivedHTTPResponse = False
  # SEND our ACK packet
  print ("Sending ACK packet")
  reply =sr1(ACK, timeout=10)
  print ("Done Sending ACK packet!")
  if reply == None:
    return NO_RESPONSE_ACK_1
  ACK2 = ip/TCP(sport=SYNACK.dport, dport=80, flags="A", seq=reply.ack, ack=SYNACK.seq+1) / (req[firstPartLen:] + "\r\n\r\n")
  receivedHTTPResponse = False
  reply = sr1(ACK2, timeout=10)
  time.sleep(2)
  if reply == None:
    print("Did not receive an ACK back")
    return NO_RESPONSE_ACK_2
  
  # wait for sniffer to get http response
  time.sleep(2) # sleeps for two seconds
  if receivedHTTPResponse == 1:
    # this request was not censored
    return RECEIVED_HTTP_RESPONSE
  elif receivedHTTPResponse > 1:
    return RECEIVED_HTTP_STATUS_MSG
  else:
    # this request was censored
    return NO_HTTP_RESPONSE

def send_packet_single(ip, req, firstPartLen):
  global receivedHTTPResponse
  ip = IP(dst=ip)       
  # Generate random source port number
  port = randint(2000, 60000)
  # Create SYN packet
  SYN=ip/TCP(sport=port, dport=80, flags="S", seq=42)
  # Send SYN and receive SYN,ACK
  print ("Sending SYN packet")
  SYNACK=sr1(SYN, timeout=5)
  print ("Receiving SYN,ACK packet")
  # could not establish connection with destination
  if SYNACK == None:
    print ("Did not receive SYNACK")
    return NO_RESPONSE_SYNACK
  # Create ACK packet
  ACK=ip/TCP(sport=SYNACK.dport, dport=80, flags="A", seq=SYNACK.ack, ack=SYNACK.seq+1) / (req[:firstPartLen] + "\r\n" + req[firstPartLen:] + "\r\n\r\n")
  receivedHTTPResponse = False
  # SEND our ACK packet
  print ("Sending ACK packet")
  reply =sr1(ACK, timeout= 10)
  print ("Done Sending ACK packet!")
  time.sleep(2)
  if reply == None:
    print("Did not receive an ACK back")
    return NO_RESPONSE_ACK_1
  # wait for sniffer to get http response
  time.sleep(2)
  if receivedHTTPResponse == 1:
    # this request was not censored
    return RECEIVED_HTTP_RESPONSE
  elif receivedHTTPResponse > 1:
    return RECEIVED_HTTP_STATUS_MSG
  else:
    # this request was censored
    return NO_HTTP_RESPONSE


def minstring(ip, request, num_iter=10):
  responses = []
  firstPartLen = request.index("Host:")
  responses.append(list(request[:firstPartLen] + "\r\n" + request[firstPartLen:] + "\r\n\r\n"))
      
  for j in range(num_iter):
    result_string = list(request)
    # replaces the ith character with "*" and sends it to GFW
    for i in range(len(request)):
      request_list = list(request)
      request_list[i] = "*"
      request_joined = "".join(request_list)
    
      # sends the request to GFW
      result = "None"
      res1 = send_packet_single(ip, request_joined, firstPartLen)
      print("### Result for ", request_joined, res1, "###")
      if res1 == NO_RESPONSE_SYNACK:
        result_string[i] = "!"
      elif res1 == NO_RESPONSE_ACK_1:
        result_string[i] = "@"
      elif res1 == NO_RESPONSE_ACK_2:
        result_string[i] = "#"
      elif res1 == NO_HTTP_RESPONSE:
        result_string[i] = "$"
      elif res1 == RECEIVED_RESPONSE:
        result_string[i] = "%"
      elif res1 == RECEIVED_HTTP_RESPONSE:
        continue
      elif res1 == RECEIVED_HTTP_STATUS_MSG:
        result_string[i] = "^"
    fullNewReq = list("".join(result_string[:firstPartLen]) + "\r\n" + "".join(result_string[firstPartLen:]) + "\r\n\r\n")
    responses.append(fullNewReq)

    print("\n\n##### RESULTS: #####")
    print("iteration #:" + str(j))
    print("Original Request: " + request[:firstPartLen] + "\r\n" + request[firstPartLen:] + "\r\n\r\n") 
    print("Minstring Result:\n" + "".join(fullNewReq))
    print ("####################")
  with open('response.pickle', 'w') as f:
    pickle.dump([responses], f)

# SNIFFER
def sniffer(pkt):
  global receivedHTTPResponse
  if "I'mHere" in str(pkt):
    receivedHTTPResponse = 1
  elif "501 Unsupported method" in str(pkt) or "400" in str(pkt):
    receivedHTTPResponse = 2
  else:
    receivedHTTPResponse = 0

def run_sniffer():
  print("Sniffer Started")
  sniff(prn=sniffer, store=0, filter="tcp port 80 and src host " + ip)

def signal_handler(signal, frame):
  sys.exit(0)
  

# MAIN
# starting the sniffer thread
t = threading.Thread(target=run_sniffer)
t.daemon = True
t.start()

ip = "52.42.171.245"
basic_request = "GET / HTTP/1.1Host: www.espn.com"
#firstPartLen = basic_request.index("Host:")
minstring(ip, basic_request)

# Ctrl-C Handler
signal.signal(signal.SIGINT, signal_handler)

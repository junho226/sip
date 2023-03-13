import os
import socket
import time
import random
import uuid
import re
from datetime import datetime
from struct import *

def parse_header(header, headers):
    lines = header.split('\r\n')[1:]
    tmp = dict(map(lambda x: (x.split(': ')[0], x), lines))
    if 'Route' in headers:
        tmp.pop('Route', None)
    if 'User-Agent' in headers:
        tmp.pop('User-Agent', None)
    if 'Contact' in headers:
        tmp.pop('Contact', None)
    headers.update(tmp)
    
    return headers

def create_register1():
    tag = random.getrandbits(32)
    branch = 'z9hG4bK' + str(random.getrandbits(32))
    call_id = str(uuid.uuid4())
    ip_from = '2001:4430:10e1:924b::62:4a1b'
    ip_to = '2001:4430:5:401::31'
    user_agent = 'TTA-VoLTE/1.0 SM-N910S/SA1 Device_Type/Android_Phone SKT'
    cell_id = 4500690010920611
    phone_number = 51218616
    register = '''REGISTER sip:lte-lguplus.co.kr SIP/2.0
Expires: 600000
Route: <sip:[{ip_to}]:5060;lr>
User-Agent: TTA-VoLTE/1.0 SM-N910S/SA1 Device_Type/Android_Phone SKT
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp={cell_id}
Allow: INVITE,ACK,OPTIONS,CANCEL,BYE,UPDATE,INFO,REFER,NOTIFY,MESSAGE,PRACK
Supported: path
Contact: <sip:010{phone_num}@[{ip_from}]:5060>;q=1.00;video;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip;v_cc
Authorization: Digest username="4500610{phone_num}@lte-lguplus.co.kr",realm="lte-lguplus.co.kr",algorithm=AKAv1-MD5,nonce="",uri="sip:lte-lguplus.co.kr",response=""
From: <sip:010{phone_num}@lte-lguplus.co.kr>;tag={tag}
To: <sip:010{phone_num}@lte-lguplus.co.kr>
Call-ID: {call_id}@{ip_from}
CSeq: 1 REGISTER
Max-Forwards: 70
Via: SIP/2.0/UDP [{ip_from}]:5060;branch={branch}smg
Content-Length: 0

'''.format(ip_to=ip_to, cell_id=cell_id, phone_num=phone_number, )

    register = register.replace('\n', '\r\n').encode()

    return register

def create_register2(nonce):
    res = 'b423dd2081fa14e76ab9c41ea2fc7b0e'
    register = '''REGISTER sip:lte-lguplus.co.kr SIP/2.0
Expires: 600000
Route: <sip:[2001:4430:5:401::31]:5060;lr>
User-Agent: TTA-VoLTE/1.0 SM-N910S/SA1 Device_Type/Android_Phone SKT
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=4500690010920611
Allow: INVITE,ACK,OPTIONS,CANCEL,BYE,UPDATE,INFO,REFER,NOTIFY,MESSAGE,PRACK
Supported: path
Authorization: Digest username="450061076587539@lte-lguplus.co.kr",realm="lte-lguplus.co.kr",nonce="{}",algorithm=AKAv1-MD5,uri="sip:lte-lguplus.co.kr",response="00000000000000000000000000000000"
Contact: <sip:01076587539@[2001:4430:178:87c1::cb:a1b]:5060>;q=1.00;audio;video;+g.3gpp.smsip;+sip.instance="<urn:gsma:imei:35467806-732959-0>";v_cc
From: <sip:01076587539@lte-lguplus.co.kr>;tag=3210654491
To: <sip:01076587539@lte-lguplus.co.kr>
Call-ID: A8486F315869AD36E9AF213F@2001:4430:178:87c1::cb:a1b
CSeq: 2 REGISTER
Max-Forwards: 70
Via: SIP/2.0/UDP [2001:4430:178:87c1::cb:a1b]:5060;branch=z9hG4bK1899853002smg
Content-Length: 0

'''.format(nonce)

    register = register.replace('\n', '\r\n').encode()

    return register

def create_unregister():
    unregister = '''REGISTER sip:lte-lguplus.co.kr SIP/2.0
Route: <sip:[2001:4430:5:401::31]:5060;lr>
User-Agent: TTA-VoLTE/1.0 SM-N910S/SA1 Device_Type/Android_Phone SKT
Allow: INVITE,ACK,OPTIONS,CANCEL,BYE,UPDATE,INFO,REFER,NOTIFY,MESSAGE,PRACK
Supported: path
Expires: 0
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=4500690010920611
Contact: <sip:01076587539@[2001:4430:178:87c1::cb:a1b]:5060>;q=1.00;audio;video;+g.3gpp.smsip;+sip.instance="<urn:gsma:imei:35467806-732959-0>";v_cc
Authorization: Digest username="450061076587539@lte-lguplus.co.kr",realm="lte-lguplus.co.kr",nonce="094MTd9IaCVFdfhPLvebB/8edR0Hf4AAr5qF1esyO/k=",algorithm=AKAv1-MD5,uri="sip:lte-lguplus.co.kr",response="00000000000000000000000000000000"
From: <sip:01076587539@lte-lguplus.co.kr>;tag=3210654491
To: <sip:01076587539@lte-lguplus.co.kr>
Call-ID: A8486F315869AD36E9AF213F@2001:4430:178:87c1::cb:a1b
CSeq: 3 REGISTER
Max-Forwards: 70
Via: SIP/2.0/UDP [2001:4430:178:87c1::cb:a1b]:5060;branch=z9hG4bK1899853002smg
Content-Length: 0

'''


    unregister = unregister.replace('\n', '\r\n').encode()

    return unregister

def create_invite():
    tag = random.getrandbits(32)
    branch = 'z9hG4bK' + str(random.getrandbits(32))
    ip_from = '2001:4430:10e1:924b::62:4a1b'
    ip_to = '2001:4430:5:401::31'
    model = 'SM-N910S'
    call_id = str(uuid.uuid4())
    
    # num_from = '01076587539'
    num_from = '01051218616'
    num_to = '01026987389'
    port = 1234
    o = round((datetime.utcnow() - datetime(1900, 1, 1, 0, 0, 0)).total_seconds())
    
    body = '''v=0
o={} {} {} IN IP6 {}
s=-
i=A VOIP Session
c=IN IP6 {}
t=0 0
m=audio {} RTP/AVP 100 96 107 101
b=AS:49
b=RS:0
b=RR:2500
a=pcfg:1 t=1
a=rtpmap:100 AMR-WB/16000/1
a=fmtp:100 octet-align=1
a=rtpmap:96 AMR/8000/1
a=fmtp:96 octet-align=1
a=rtpmap:107 telephone-event/16000
a=fmtp:107 0-15
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=candidate:1 1 UDP 2130706431 {} {} typ host
a=sendrecv
a=ptime:20
a=maxptime:120
'''.format(num_from, o, o, ip_from, ip_from, port, ip_from, port)
    
    body = body.replace('\n', '\r\n')
    body = body.encode()
    
    content_length = len(body)
    
    header = '''INVITE tel:{};phone-context=lte-lguplus.co.kr SIP/2.0
Supported: timer,100rel
P-Early-Media: supported
Allow: INVITE,ACK,OPTIONS,CANCEL,BYE,UPDATE,INFO,REFER,NOTIFY,MESSAGE,PRACK
P-Preferred-Identity: <sip:{}@lte-lguplus.co.kr>
P-TTA-VoLTE-Info: avchange
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=4500690010920611
Session-Expires: 3600;refresher=uac
Min-SE: 90
Content-Type: application/sdp
Route: <sip:[{}]:5060;lr>
Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";require;explicit
P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel
User-Agent: TTA-VoLTE/1.0 {}/SA1 Device_Type/Android_Phone SKT
From: <sip:{}@lte-lguplus.co.kr>;tag={}
To: <tel:{};phone-context=lte-lguplus.co.kr>
Call-ID: {}@{}
CSeq: 1 INVITE
Max-Forwards: 70
Contact: <sip:{}@[{}]:5060>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";video
Via: SIP/2.0/UDP [{}]:5060;branch={}smg
Content-Length: {}
'''.format(num_to, num_from, ip_to, model, num_from, tag, num_to, call_id, ip_from, num_from, ip_from, ip_from, branch, content_length)
    header = header.replace('\n', '\r\n')   
    headers = parse_header(header, {}) 
    header = header.encode()
    
    return header + '\r\n'.encode() + body, headers

def create_cancle(headers):
    headers['Content-Length'] = 'Content-Length: 0'
    headers['CSeq'] = 'CSeq: 1 CANCEL'
    header_list = ['Call-ID', 'CSeq', 'From', 'Route', 'Via', 'To', 'Contact', 'Max-Forwards', 'Content-Length']
    payload = 'CANCEL ' + re.search(r'<(.*?)>', headers['To']).group(1) +  ' SIP/2.0\r\n'

    for header in header_list:
        payload += headers[header] + '\r\n'
    
    payload += '\r\n'
    
    return payload.encode(), headers

def create_ack(headers):
    seq = headers['CSeq'].split(': ')[1].split()[0]
    headers['CSeq'] = 'CSeq: {} ACK'.format(seq)
    headers['Content-Length'] = 'Content-Length: 0'
    header_list = ['Allow', 'Call-ID', 'CSeq', 'From', 'User-Agent', 'Route', 'Via', 'To', 'Max-Forwards', 'Content-Length']

    payload = 'ACK ' + re.search(r'<(.*?)>', headers['Route']).group(1).replace('lr', 'transport=UDP') + ' SIP/2.0\r\n' 

    for header in header_list:
        payload += headers[header] + '\r\n'
    
    payload += '\r\n'
    
    print(payload)
    
    return payload.encode(), headers

def create_dummy(seq, timestamp, ssrc):
    payload = b'\xf0' + os.urandom(61)
    if seq == 1:
        start = b'\x80\xe4'
    else:
        start = b'\x80\x64'
    
    return start + pack('!HII', seq%65536, timestamp, ssrc) + payload

def send_rtp(ip, port):
    rtp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    rtp.setsockopt(socket.SOL_SOCKET, 25, b'rmnet0')
    # rtp.bind((b'0.0.0.0', 1234))

    ssrc = random.getrandbits(32)
    seq = 1

    while True:

        timestamp = round(time.time())
        payload = create_dummy(seq, timestamp, ssrc)
        rtp.sendto(payload, (ip, port))
        time.sleep(2)
    

def main():
    # sip_addr = "125.144.112.66"
    sip_addr = "2001:4430:5:401::31"
    sip_port = 5060

    receiver = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP)
    receiver.setsockopt(socket.SOL_SOCKET, 25, b'rmnet0')
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sender = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sender.setsockopt(socket.SOL_SOCKET, 25, b'rmnet0')
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print("######## Sending Invite ########\n")

    # payload, headers = create_invite()
    payload = create_register1()    
    # payload = create_unregister()
    sender.sendto(payload, (sip_addr, sip_port))
    print(payload, '\n\n')
    t = time.time()
    cnt = 0
    
    while True:
        data, addr = receiver.recvfrom(65565)
        # start = (data[0]&0xf)*4+8
        data = data[8:]
        if data[0] == 128 or data[0] == 129:
            continue
        
        data = data.decode()
        print(data)
        if cnt > 0:
            return
        unauth = data.split('"')
        nonce = unauth[unauth.index(',nonce=')+1]
        payload = create_register2(nonce) 
        sender.sendto(payload, (sip_addr, sip_port))
        print(payload, '\n\n')
        # header, body = data.split('\r\n\r\n', 1)
        
        
        # headers = parse_header(header, headers)
        
        # header = header.split('\r\n')
        # method = header[0].split()
        # header = header[1:]
        # response, code, name = method
        
        # if response == 'SIP/2.0':
        #     print(code, name)
        #     if code == '100':
        #         continue
            
        #     elif code == '183':
        #         pass
            
        #     elif code == '200':
                
        #         rname = headers['CSeq'].split(': ')[1].split()[1]
                
        #         if rname == 'INVITE':
        #             print('Receive INVITE')
        #             packet_ack, headers = create_ack(headers)
        #             sender.sendto(packet_ack, (sip_addr, sip_port))
                    
        #             ip = re.search(r'c=IN IP6 (.*?)\r\n', body).group(1)
        #             port = int(re.search(r'm=audio (.*?) RTP', body).group(1))

        #             print('################################')
        #             print("########  Call Session  ########")
        #             print('################################\n')
                    
        #             send_rtp(ip, port)
                    
        #     elif code in ['380', '401', '403', '408', '481', '500', '487']:
        #         packet_ack, headers = create_ack(headers)
        #         sender.sendto(packet_ack, (sip_addr, sip_port))
        #     else:
        #         print('################################')
        #         print("########  Unknown Code  ########")
        #         print('################################\n')
                
        #         print(data)
                
        # elif response == 'BYE':
        #     pass
        
        # else:
        #     print('################################')
        #     print("#######  Abnormal Packet  ######")
        #     print('################################\n')
        if time.time() - t > 20:
            return
        cnt += 1
        

if __name__ == '__main__':
    main()

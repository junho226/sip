import os
import socket
import time
import random
import uuid
import re
from datetime import datetime
from struct import *
from threading import Thread, Event


class sip():

    def __init__(self, mno):
        self.mno = mno
        self.headers = {}
        self.ip_from = '2001:4430:f5:ebf0::58a:a1b'
        self.ip_to = '2001:4430:5:401::26'
        self.user_agent = 'TTA-VoLTE/1.0 SM-N910S/SA1 Device_Type/Android_Phone SKT'
        self.src_num = '01076587539'
        self.dst_num = '01084647530'
        self.src_port = 1230
        self.tag = random.getrandbits(32)
        self.branch = str(random.getrandbits(32))
        self.call_id = str(uuid.uuid4())
        
    def update_parameters(self):
        self.tag = random.getrandbits(32)
        self.branch = str(random.getrandbits(32))
        self.call_id = str(uuid.uuid4())
        

    def parse_header(self, header):
        headers = self.headers
        lines = header.split('\r\n')[1:]
        tmp = dict(map(lambda x: (x.split(': ')[0], x), lines))
        if 'Route' in headers:
            tmp.pop('Route', None)
        if 'User-Agent' in headers:
            tmp.pop('User-Agent', None)
        if 'Contact' in headers:
            tmp.pop('Contact', None)
        headers.update(tmp)
        
        self.headers = headers
        
        return self.headers

    def create_register1(self):
        tag = random.getrandbits(32)
        branch = str(random.getrandbits(32))
        call_id = str(uuid.uuid4())
        ip_from = '2001:4430:10e1:924b::62:4a1b'
        ip_to = '2001:4430:5:401::31'
        user_agent = 'TTA-VoLTE/1.0 SM-N910S/SA1 Device_Type/Android_Phone SKT'
        cell_id = 4500690010920611
        phone_number = 51218616
        register = '''REGISTER sip:lte-lguplus.co.kr SIP/2.0
Expires: 600000
Route: <sip:[{ip_to}]:5060;lr>
User-Agent: {user_agent}
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
Via: SIP/2.0/UDP [{ip_from}]:5060;branch=z9hG4bK{branch}smg
Content-Length: 0

'''.format(ip_to=ip_to, user_agent=user_agent, cell_id=cell_id, phone_num=phone_number, ip_from=ip_from, tag=tag, call_id=call_id, branch=branch)

        register = register.replace('\n', '\r\n').encode()

        return register

    def create_register2(self, nonce):
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

    def create_unregister(self, nonce):
        unregister_key = ['Route', 
                          'User-Agent', 
                          'Allow', 
                          'Supported', 
                          'Expires', 
                          'P-Access-Network-Info', 
                          'Contact', 
                          'Authorization', 
                          'From', 
                          'To', 
                          'Call-ID', 
                          'CSeq', 
                          'Max-Forwards', 
                          'Via', 
                          'Content-Length']
        
        unregister = '''REGISTER sip:lte-lguplus.co.kr SIP/2.0
Route: <sip:[2001:4430:5:401::31]:5060;lr>
User-Agent: TTA-VoLTE/1.0 SM-N910S/SA1 Device_Type/Android_Phone SKT
Allow: INVITE,ACK,OPTIONS,CANCEL,BYE,UPDATE,INFO,REFER,NOTIFY,MESSAGE,PRACK
Supported: path
Expires: 0
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=4500690010920611
Contact: <sip:01076587539@[2001:4430:178:87c1::cb:a1b]:5060>;q=1.00;audio;video;+g.3gpp.smsip;+sip.instance="<urn:gsma:imei:35467806-732959-0>";v_cc
Authorization: Digest username="450061076587539@lte-lguplus.co.kr",realm="lte-lguplus.co.kr",nonce="{nonce}",algorithm=AKAv1-MD5,uri="sip:lte-lguplus.co.kr",response="00000000000000000000000000000000"
From: <sip:01076587539@lte-lguplus.co.kr>;tag=3210654491
To: <sip:01076587539@lte-lguplus.co.kr>
Call-ID: A8486F315869AD36E9AF213F@2001:4430:178:87c1::cb:a1b
CSeq: 3 REGISTER
Max-Forwards: 70
Via: SIP/2.0/UDP [2001:4430:178:87c1::cb:a1b]:5060;branch=z9hG4bK1899853002smg
Content-Length: 0

'''.format(nonce=nonce)

        unregister = unregister.replace('\n', '\r\n').encode()

        return unregister

    def create_invite(self):
        uri = 'lte-lguplus.co.kr'
        tag = random.getrandbits(32)
        branch = 'z9hG4bK' + str(random.getrandbits(32))
        ip_from = '2001:4430:f5:ebf0::58a:a1b'
        ip_to = '2001:4430:5:401::26'
        model = 'SM-N910S'
        call_id = str(uuid.uuid4())
        cell_id = 4500690010920611
        
        num_from = '01076587539'
        # num_from = '01051218616'
        num_to = '01084647530'
        port = 1230
        o = round((datetime.utcnow() - datetime(1900, 1, 1, 0, 0, 0)).total_seconds())
        
        body = '''v=0
o={num_from} {o} {o} IN IP6 {ip_from}
s=-
i=A VOIP Session
c=IN IP6 {ip_from}
t=0 0
m=audio {port} RTP/AVP 100 96 107 101
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
a=candidate:1 1 UDP 2130706431 {ip_from} {port} typ host
a=sendrecv
a=ptime:20
a=maxptime:120
'''.format(num_from=num_from, o=o, ip_from=ip_from, port=port)
        
        body = body.replace('\n', '\r\n')
        body = body.encode()
        
        content_length = len(body)
        
        header = '''INVITE tel:{num_to};phone-context={uri} SIP/2.0
Supported: timer,100rel
P-Early-Media: supported
Allow: INVITE,ACK,OPTIONS,CANCEL,BYE,UPDATE,INFO,REFER,NOTIFY,MESSAGE,PRACK
P-Preferred-Identity: <sip:{num_from}@{uri}>
P-TTA-VoLTE-Info: avchange
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp={cell_id}
Session-Expires: 3600;refresher=uac
Min-SE: 90
Content-Type: application/sdp
Route: <sip:[{ip_to}]:5060;lr>
Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";require;explicit
P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel
User-Agent: TTA-VoLTE/1.0 {model}/SA1 Device_Type/Android_Phone SKT
From: <sip:{num_from}@{uri}>;tag={tag}
To: <tel:{num_to};phone-context={uri}>
Call-ID: {call_id}@{ip_from}
CSeq: 1 INVITE
Max-Forwards: 70
Contact: <sip:{num_from}@[{ip_from}]:5060>;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";video
Via: SIP/2.0/UDP [{ip_from}]:5060;branch={branch}smg
Content-Length: {content_length}
'''.format(num_to=num_to, uri=uri, cell_id=cell_id, num_from=num_from, ip_to=ip_to, model=model, tag=tag, call_id=call_id, ip_from=ip_from, branch=branch, content_length=content_length)
        header = header.replace('\n', '\r\n')   
        headers = self.parse_header(header) 
        header = header.encode()
        
        return header + '\r\n'.encode() + body, headers

    def create_cancle(self):
        headers = self.headers
        headers['Content-Length'] = 'Content-Length: 0'
        headers['CSeq'] = 'CSeq: 1 CANCEL'
        header_list = ['Call-ID', 'CSeq', 'From', 'Route', 'Via', 'To', 'Contact', 'Max-Forwards', 'Content-Length']
        payload = 'CANCEL ' + re.search(r'<(.*?)>', headers['To']).group(1) +  ' SIP/2.0\r\n'

        for header in header_list:
            payload += headers[header] + '\r\n'
        
        payload += '\r\n'
        self.headers = headers
        
        return payload.encode(), headers
    
    def create_ok(self):
        headers = self.headers
        headers['Content-Length'] = 'Content-Length: 0'
        
        header_list = ['Via', 'From', 'To', 'Call-ID', 'CSeq', 'Allow', 'P-Access-Network-Info', 'User-Agent', 'Content-Length']

        payload = 'SIP/2.0 200 OK\r\n'

        for header in header_list:
            payload += headers[header] + '\r\n'
        
        payload += '\r\n'
        self.headers = headers

        return payload.encode(), headers

    def create_ack(self):
        headers = self.headers
        seq = headers['CSeq'].split(': ')[1].split()[0]
        headers['CSeq'] = 'CSeq: {} ACK'.format(seq)
        headers['Content-Length'] = 'Content-Length: 0'
        header_list = ['Allow', 'Call-ID', 'CSeq', 'From', 'User-Agent', 'Route', 'Via', 'To', 'Max-Forwards', 'Content-Length']

        payload = 'ACK ' + re.search(r'<(.*?)>', headers['Route']).group(1).replace('lr', 'transport=UDP') + ' SIP/2.0\r\n' 

        for header in header_list:
            payload += headers[header] + '\r\n'
        
        payload += '\r\n'
        
        print(payload)
        self.headers = headers
        
        return payload.encode(), headers
    
    def create_prack(self):
        headers = self.headers
        seq = headers['CSeq'].split(': ')[1].split()[0]
        headers['CSeq'] = 'CSeq: {} ACK'.format(seq+1)
        headers['RAck'] = 'RAck: {seq} {seq} INVITE'.format(seq=seq)
        headers['Content-Length'] = 'Content-Length: 0'
        header_list = ['Max-Forwards', 'Route', 'Via', 'CSeq', 'From', 'To', 'Call-ID', 'Accept-Contact', 'Allow', 'P-Preferred-Identity', 'P-Access-Network-Info', 'RAck', 'User-Agent', 'Content-Length']
        
        payload = 'PRACK ' + re.search(r'<(.*?)>', headers['Route']).group(1).replace('lr', 'transport=UDP') + ' SIP/2.0\r\n'

        for header in header_list:
            payload += headers[header] + '\r\n'

        payload += '\r\n'
        print(payload)
        self.headers = headers

        return payload.encode(), headers
    
    def create_message(self):
        tag = random.getrandbits(32)
        branch = 'z9hG4bK' + str(random.getrandbits(32))+'smg'
        ip_from = '2001:4430:f5:ebf0::58a:a1b'
        ip_to = '2001:4430:5:401::26'
        model = 'SM-N910S'
        call_id = str(uuid.uuid4())
        cell_id = 4500690010920611
        
        num_from = '01076587539'
        # num_from = '01051218616'
        num_to = '01084647530'
        port = 1230

        body = b'\x00\x04\x00\x07\x91\x28\x01\x08\x10\x50\x58\x0f\x01\x04\x0b\x81\x10\x80\x64\x74\x35\xf0\x00\x00\x02\xc8\x34' # Hi
        # body = b'\x00\x04\x00\x07\x91\x28\x01\x08\x10\x50\x58\x0f\x01\x04\x0b\x81\x10\x80\x64\x74\x35\xf0\x00\x00\x01\x20'
        
        content_length = len(body)
        
        header = '''MESSAGE sip:ipsmgw.lte-lguplus.co.kr SIP/2.0
Accept-Contact: *;+g.3gpp.smsip;explicit;require
Allow: MESSAGE
P-Preferred-Identity: <sip:{num_from}@lte-lguplus.co.kr>
Content-Type: application/vnd.3gpp.sms
Route: <sip:[{ip_to}]:5060;lr>
Request-Disposition: no-fork
User-Agent: TTA-VoLTE/1.0 SM-N910S/SA1 Device_Type/Android_Phone SKT
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=4500690010920611
From: <sip:{num_from}@lte-lguplus.co.kr>;tag={tag}
To: <sip:ipsmgw.lte-lguplus.co.kr>
Call-ID: {call_id}@{ip_from}
CSeq: 1 MESSAGE
Max-Forwards: 70
Via: SIP/2.0/UDP [{ip_from}]:5060;branch={branch}
Content-Length: {content_length}

'''.format(num_from=num_from, ip_to=ip_to, tag=tag, call_id=call_id, ip_from=ip_from, branch=branch, content_length=content_length)
        
        payload = header.replace('\n', '\r\n').encode() + body + '\r\n'.encode()
        # payload = header.replace('\n', '\r\n').encode()
        
        return payload
    
    def create_msg_reply(self):
        header = '''MESSAGE sip:ipsmgw.lte-lguplus.co.kr SIP/2.0
Accept-Contact: *;+g.3gpp.smsip;explicit;require
Allow: MESSAGE
P-Preferred-Identity: <sip:01076587539@lte-lguplus.co.kr>
Content-Type: application/vnd.3gpp.sms
In-Reply-To: MzI0OTU1NTI0LTEwNzkyLXFhem95dGk5QDEwLjEyMC4yMDAuNTI-LGU+IBCF
Route: <sip:[2001:4430:5:401::31]:5060;lr>
Request-Disposition: no-fork
User-Agent: TTA-VoLTE/1.0 SM-N910S/SA1 Device_Type/Android_Phone SKT
P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=4500690010920611
From: <sip:01076587539@lte-lguplus.co.kr>;tag=4222599910
To: <sip:ipsmgw.lte-lguplus.co.kr>
Call-ID: DF31E1134F36695F7C3FFEBC@2001:4430:f5:ebf0::58a:a1b
CSeq: 1 MESSAGE
Max-Forwards: 70
Via: SIP/2.0/UDP [2001:4430:f5:ebf0::58a:a1b]:5060;branch=z9hG4bK3933130369smg
Content-Length: 6
'''
        body = b'\x02\x84\x41\x02\x00\x00'
        
        payload = header.replace('\n', '\r\n').encode() + body + '\r\n'.encode()
        
        return payload

class rtp():
    
    def __init__(self):
        pass

    def create_dummy(self, seq, timestamp, ssrc):
        # dummy = b'\x00\x44\x95\x41\xf8\x4c\xeb\x81\x5b\x51\x8b\xc8\x30\x04\xa5\x1c\x65\x57\xdd\x98\xd3\x20\x4d\xd2\xae\xf0\x00\xde\x4a\x51\xb6\xbb\x47\x1e\x78\x9c\x04\x3c\xc8\x22\xd1\xcc\xea\x4e\x7f\xb2\x7e\xc9\x94\xd1\x9e\x93\xc1\x68\x3d\x00\x40\x98\xbf\xc2\xbc\xe8'
        sid = b'\x00\x4c\xe3\xdf\x3d\xe0\x18'
        # payload = b'\xf0' + os.urandom(61)
        if seq == 1:
            start = b'\x80\xe4'
        else:
            start = b'\x80\x64'
        
        # return start + pack('!HII', seq%65536, timestamp, ssrc) + hex
        # return start + pack('!HII', seq%65536, timestamp, ssrc) + payload
        return start + pack('!HII', seq%65536, timestamp, ssrc) + sid

    def send_audio(self, ip, port, src_port):
        rtp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        rtp.setsockopt(socket.SOL_SOCKET, 25, b'rmnet0')
        rtp.bind(('', src_port))
        
        with open('audio_test.txt', 'rb') as f:
            payloads = f.readlines()
        
        for payload in payloads:
            rtp.sendto(payload[:-1], (ip, port))
            time.sleep(0.02)
        

    def send_rtp(self, ip, port, src_port, e):
        rtp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        rtp.setsockopt(socket.SOL_SOCKET, 25, b'rmnet0')
        rtp.bind(('', src_port))

        ssrc = random.getrandbits(32)
        timestamp = random.getrandbits(32)
        timegap = 320
        seq = 1
        
        for i in range(100):
            payload = self.create_dummy(seq, timestamp, ssrc)
            rtp.sendto(payload, (ip, port))
            seq += 1
            timestamp += timegap
            time.sleep(0.02)
        
            
    def receive_rtp(self, ip, e):
        rtp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP)
        rtp.setsockopt(socket.SOL_SOCKET, 25, b'rmnet0')
        rtp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        with open('audio_test2.txt', 'wb') as f:
            while not e.is_set():
                data, addr = rtp.recvfrom(65565)
                f.write(data[8:]+b'\n')
                print(addr)
                print(data)
                
        print("Finished")
    
    
    def start_session(self, ip, port, src_port, e):
        
        # self.send_audio(ip, port, src_port)        
        
        ############## For RTP packet capture ###############
        
        sender = Thread(target = self.send_rtp, args = (ip, port, src_port, e,))
        receiver = Thread(target = self.receive_rtp, args=(ip, e,))
        sender.start()
        receiver.start()
        sender.join()
        receiver.join()
            

def main():
    # sip_addr = "125.144.112.66"
    sip_addr = "2001:4430:5:401::26"
    sip_port = 5060

    receiver = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP)
    receiver.setsockopt(socket.SOL_SOCKET, 25, b'rmnet0')
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sender = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sender.setsockopt(socket.SOL_SOCKET, 25, b'rmnet0')
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print("######## Sending Invite ########\n")
    
    s = sip('LG')
    r = rtp()
    
    payload, headers = s.create_invite()
    # payload = s.create_message()

    # payload = create_register1()    
    # payload = create_unregister()
    sender.sendto(payload, (sip_addr, sip_port))
    print(payload, '\n\n')
    t = time.time()
        
    e = Event()
    
    while True:
        data, addr = receiver.recvfrom(65565)
        # start = (data[0]&0xf)*4+8
        data = data[8:]
        if data[0] == 128 or data[0] == 129:
            continue
        
        data = data.decode()
        print(data)
        
        # unauth = data.split('"')
        # nonce = unauth[unauth.index(',nonce=')+1]
        # payload = create_register2(nonce) 
        # sender.sendto(payload, (sip_addr, sip_port))
        # print(payload, '\n\n')
        
        
        header, body = data.split('\r\n\r\n', 1)
        
        
        headers = s.parse_header(header)
        
        header = header.split('\r\n')
        method = header[0].split()
        header = header[1:]
        response = method[0]
        code = method[1]
        name = ' '.join(method[2:])
        
        if response == 'SIP/2.0':
            print(code, name)
            if code in ['100', '180']:
                continue
            
            elif code == '183':
                packet_prack, headers = s.create_prack()
                sender.sendto(packet_prack, (sip_addr, sip_port))
            
            elif code == '200':
                
                rname = headers['CSeq'].split(': ')[1].split()[1]
                
                if rname == 'INVITE':
                    print('Receive INVITE')
                    packet_ack, headers = s.create_ack()
                    sender.sendto(packet_ack, (sip_addr, sip_port))
                    
                    ip = re.search(r'c=IN IP6 (.*?)\r\n', body).group(1)
                    port = int(re.search(r'm=audio (.*?) RTP', body).group(1))

                    print('################################')
                    print("########  Call Session  ########")
                    print('################################\n')
                    
                    print(ip, port, '\n')
                    # r.send_rtp(ip, port, src_port=1230)
                    # r.receive_rtp()
                    r.start_session(ip, port, src_port=1230, e=e)
                    
            elif code in ['380', '401', '403', '408', '481', '500', '487']:
                packet_ack, headers = s.create_ack()
                sender.sendto(packet_ack, (sip_addr, sip_port))
                return
            else:
                print('################################')
                print("########  Unknown Code  ########")
                print('################################\n')
                
                print(data)
                return
                
        elif response == 'BYE':
            e.set()
            print("e set")
            return
        
        else:
            print('################################')
            print("#######  Abnormal Packet  ######")
            print('################################\n')
            print(data)
            return
        

if __name__ == '__main__':
    main()

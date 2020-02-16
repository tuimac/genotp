import os
import sys
import hmac
import hashlib
import time
import datetime
import base64

class Totp:
    def __init__(self, interval, digits, iamuser, path):
        self.interval = interval
        self.digits = digits
        self.iamuser = iamuser
        self.path = path
   
    def get_remaintime(self):
        return self.interval - long(time.mktime(datetime.datetime.now().timetuple())) % self.interval

    def get_secretkey(self, iamuser):
        key_path = os.path.expanduser(self.path + iamuser)
        secret_key = ""

        with open(key_path, 'r') as file:
            os.chmod(key_path, 0644)
            secret_key = file.read()
            os.chmod(key_path, 0400)
            if secret_key == "":
                print "Please check out secret key file permission.\nex) 'Own[user:user],Permission[400]' is OK."
        return secret_key

    def get_messagekey(self, seed):
        hash_map = {
            'A':0, 'B':1, 'C':2, 'D':3, 'E':4, 'F':5, 'G':6, 'H':7,
            'I':8, 'J':9, 'K':10, 'L':11,'M':12, 'N':13, 'O':14, 'P':15,
            'Q':16, 'R':17, 'S':18, 'T':19, 'U':20, 'V':21, 'W':22, 'X':23,
            'Y':24, 'Z':25, '2':26, '3':27, '4':28, '5':29, '6':30, '7':31
        }
        seed = seed.replace('\n', '')
        decoded_key = hash_map[seed[0]]
        for i in range(1, len(seed)):
            decoded_key <<= 5
            decoded_key += hash_map[seed[i]]
        msg = bytearray()
        while(decoded_key > 0):
            msg.append(decoded_key & 0xff)
            decoded_key >>= 8
        return bytes(bytearray(reversed(msg)))

    def get_timekey(self, interval):
        unix_time = long(time.mktime(datetime.datetime.now().timetuple())) / interval
        time_key = bytearray()
        while(unix_time > 0):
            time_key.append(unix_time & 0xff)
            unix_time >>= 8
        return bytes(bytearray(reversed(time_key)).rjust(8, b'\0'))

    def get_otp(self, msg, time):
        hmac_obj = hmac.new(msg, time, hashlib.sha1)
        digest_msg = bytearray(hmac_obj.digest())
        
        offset = digest_msg[-1] & 0xf
        binary_code = (digest_msg[offset] & 0x7f) << 24
        binary_code += (digest_msg[offset + 1] & 0xff) << 16
        binary_code += (digest_msg[offset + 2] & 0xff) << 8
        binary_code += (digest_msg[offset + 3] & 0xff)
        
        otp = str(binary_code % (10 ** self.digits))
        while len(otp) < self.digits: otp = "0" + otp
        return otp

    def get_number(self):
        seed = self.get_secretkey(self.iamuser)
        msg_key = self.get_messagekey(seed)
        time_key = self.get_timekey(self.interval)
        return self.get_otp(msg_key, time_key)

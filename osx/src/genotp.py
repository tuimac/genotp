#!/usr/bin/env python3

from getpass import getpass
import signal
import argparse
import subprocess
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
        return self.interval - int(time.mktime(datetime.datetime.now().timetuple())) % self.interval

    def get_secretkey(self, iamuser):
        key_path = os.path.expanduser(self.path + iamuser)
        secret_key = ""

        with open(key_path, 'r') as file:
            os.chmod(key_path, 0o644)
            secret_key = file.read()
            os.chmod(key_path, 0o400)
            if secret_key == "":
                print("Please check out secret key file permission.\nex) 'Own[user:user],Permission[400]' is OK.")
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
        unix_time = int(time.mktime(datetime.datetime.now().timetuple()) / interval)
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

def list_name(secret_path):
    print("# Here is registered IAM users.\n")
    index = 1
    for filename in os.listdir(secret_path):
        filename = str(index) + ". " + filename
        print(filename)
        index += 1
    print("")

def delete_secretkey(secret_path, targets):
    failedlist = []
    sys.stdout.write("# Delete Following IAM user's keys.\n>> ")
    for target in targets: sys.stdout.write(target + " ")
    while True:
        answer = raw_input("\n\nIs that OK? [Y,y]yes [N,n]No : ").upper()
        if answer == "N":
            print("Quit delete keys...")
            sys.exit(0)
        elif answer == "Y": break
        else: print("You have to answer 'Y' of 'N'.")

    for target in targets:
        filename = secret_path + target
        if os.path.exists(filename) is False:
            failedlist.append(target)
            continue
        os.remove(filename)
        if os.path.exists(filename) is True:
            failedlist.append(target)
    if len(failedlist) > 0:
        sys.stdout.write("Failed to remove following IAM user's secret key: ")
        print(", ".join(failedlist))
        sys.exit(1)
    print("\nDelete successed!\n")

def register_secretkey(secret_path, iamuser):
    if os.path.exists(secret_path) is False: os.makedirs(secret_path)
    filepath = secret_path + iamuser
    if os.path.exists(filepath):
        print("That IAM user have already been there so quit register key process..,")
        sys.exit(1)
    print("\n# Paste your secret key below. Then press Enter.\n")
    while True:
        secret_key = getpass("Paste key: ")
        if secret_key != "": break
    with open(filepath, 'w') as f:
        f.write(secret_key)
    os.chown(filepath, os.geteuid(), os.getgid())
    os.chmod(filepath, 0o400)
    print("\nResister secret key successed!\n")

def display_number(totp, interval):
    while True:        
        number = totp.get_number()
        remaintime = totp.get_remaintime()
        print(number)
        for j in range(interval - remaintime, interval):
            display = "["
            for i in range(interval):
                if i <= j: display += "#"
                else: display += " "
            display += "]"
            sys.stdout.write("\r%s" % display)
            sys.stdout.flush()
            time.sleep(1)
        print("")

def arg_parser(secret_path, iamuser):
    parser = argparse.ArgumentParser(
        prog='genotp',
        description='This program run on UNIX base machine.',
        add_help=True,
    )
    parser.add_argument(
        'iam',
        nargs='?',
        metavar='<IAM user name>',
        help="Display each IMA user's one time password.",
    )
    parser.add_argument(
        '-r',
        '--register',
        dest='register',
        nargs=1,
        metavar='<IAM user name>',
        help='Register secret key for new IAM user.',
    )
    parser.add_argument(
        '-l',
        '--list',
        nargs='?',
        dest='list',
        default='default',
        help='Show registered IAM user.'
    )
    parser.add_argument(
        '-d',
        '--delete',
        dest='delete',
        nargs='*',
        help='Delete registered IAM user.'
    )
    args = parser.parse_args()
    if args.list is None:
        list_name(secret_path)
        sys.exit(0)
    if args.register:
        register_secretkey(secret_path, args.register[0])
        sys.exit(0)
    if args.delete:
        delete_secretkey(secret_path, args.delete)
        sys.exit(0)
    if args.iam:
        if os.path.exists(secret_path + iamuser[1]) is False:
            print("There is no such a IAM user was registed...")
            sys.exit(1)

def signal_handler(signum, frame):
    print("")
    sys.exit(1)

if __name__ == '__main__':
    interval = 30
    digits = 6
    secret_path = os.path.expanduser('~') + "/.mfa/"
    
    try:
        sys.tracebacklimit = 0
        signal.signal(signal.SIGINT, signal_handler)
        arg_parser(secret_path, sys.argv)
        display_number(Totp(interval, digits, sys.argv[1], secret_path), interval)
    except:
        pass

#!/usr/bin/env python

from totp import Totp
from getpass import getpass
from sys import exit
from time import sleep
import sys
import os
import time
import signal
import argparse
import subprocess

def list_name(secret_path):
    print "# Here is registered IAM users.\n" 
    index = 1
    for filename in os.listdir(secret_path):
        filename = str(index) + ". " + filename
        print filename
        index += 1
    print ""

def delete_secretkey(secret_path, targets):
    failedlist = []
    sys.stdout.write("# Delete Following IAM user's keys.\n>> ")
    for target in targets: sys.stdout.write(target + " ")
    while True:
        answer = raw_input("\n\nIs that OK? [Y,y]yes [N,n]No : ").upper()
        if answer == "N":
            print "Quit delete keys..."
            exit(0)
        elif answer == "Y": break
        else: print "You have to answer 'Y' of 'N'."

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
        print ", ".join(failedlist)
        exit(1)
    print "\nDelete successed!\n"

def register_secretkey(secret_path, iamuser):
    if os.path.exists(secret_path) is False: os.makedirs(secret_path)
    filepath = secret_path + iamuser
    if os.path.exists(filepath):
        print "That IAM user have already been there so quit register key process..,"
        exit(1)
    print "\n# Paste your secret key below. Then press Enter.\n"
    while True:
        secret_key = getpass("Paste key: ")
        if secret_key != "": break
    with open(filepath, 'w') as f:
        f.write(secret_key)
    os.chown(filepath, os.geteuid(), os.getgid())
    os.chmod(filepath, 0400)
    print "\nResister secret key successed!\n"

def display_number(totp, interval):
    while True:        
        number = totp.get_number()
        remaintime = totp.get_remaintime()
        print number
        for j in range(interval - remaintime, interval):
            display = "["
            for i in range(interval):
                if i <= j: display += "#"
                else: display += " "
            display += "]"
            sys.stdout.write("\r%s" % display)
            sys.stdout.flush()
            time.sleep(1)
        print ""

def arg_parser(secret_path, iamuser):
    parser = argparse.ArgumentParser(
        prog='mfa',
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
        exit(0)
    if args.register:
        register_secretkey(secret_path, args.register[0])
        exit(0)
    if args.delete:
        delete_secretkey(secret_path, args.delete)
        exit(0)
    if args.iam:
        if os.path.exists(secret_path + iamuser[1]) is False:
            print "There is no such a IAM user was registed..."
            exit(1)

def signal_handler(signum, frame):
    print ""
    exit(1)

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

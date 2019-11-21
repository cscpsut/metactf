from netmiko import *
from paramiko import *
import getpass
import logging

hostname = ""
ip = ""
connection = None


def verification():
    affirm = {'y', 'yes'}
    negative = {'n', 'no'}
    keyword = ''
    while 1:
        verify = input("Do you want to verify from running-configuration? [Y]") or 'Y'
        if verify.lower() in affirm or verify.lower() in negative:
            if verify.lower() == 'y' or verify.lower() == 'yes':
                while 1:
                    keyword = input("String to check for in Running Config for verification: (Can't be empty)")
                    if keyword:
                        break
                break
            else:
                break
        else:
            while 1:
                verify = input("Please enter Yes or No [Y/N]: ")
                if verify in affirm or verify in negative:
                    if verify.lower() == 'y' or verify.lower() == 'yes':
                        while 1:
                            keyword = input("String to check for in Running Config for verification: (Can't be empty)")
                            if keyword:
                                break
                        break
                    else:
                        break
            break
    return keyword


def connectiontype():
    while 1:
        con_type = input("SSH or Telnet? [SSH]") or 'SSH'
        if con_type.lower() == 'telnet' or con_type.lower() == 'ssh':
            if con_type.lower() == 'telnet':
                con_type = 'telnet'
                break
            elif con_type.lower() == 'ssh':
                break
        else:
            continue
    return con_type.lower()


def verifykeyword(keyword):
    verified = connection.send_command("show running-config | inc " + keyword)
    if verified:
        logging.info("[+] Success: [IP]: %s  [Hostname]: %s" % (ip.strip('\n'), hostname.split()[1]))
        print("[+] Verified: \n%s" % verified)
        print("[+] Success: [IP]: %s  [Hostname]: %s" % (ip.strip('\n'), hostname.split()[1]))
        connection.save_config()
    else:
        logging.error("[+] Failed: [IP]: %s  [Hostname]: %s  (Reason: Verification failed)" % (ip.strip('\n'),
                                                                                               hostname.split()[1]))
        print("[+] Failed: [IP]: %s  [Hostname]: %s  (Reason: Verification failed)" % (ip.strip('\n'),
                                                                                       hostname.split()[1]))


def main():
    global hostname
    global ip
    global connection
    con_type = connectiontype()
    logfile = input("Enter logfile name: [cisco.log]") or 'cisco.log'
    logging.basicConfig(filename=logfile, level=logging.DEBUG)
    iplist = input("Enter IP List file name: [iplist.txt]") or 'iplist.txt'
    config = input("Enter Configuration file name: [config.txt]") or 'config.txt'
    keyword = verification()
    user = input("Enter your username: [admin]") or 'admin'
    passwd = getpass.getpass(prompt='Password:')
    secret = getpass.getpass(prompt='Secret:')
    print("\nAutomating...")
    ips = open(iplist, 'r')
    for ip in ips:
        try:
            if con_type == 'ssh':
                connection = ConnectHandler(device_type='cisco_ios', host=ip, username=user, password=passwd,
                                            secret=secret)
            else:
                connection = ConnectHandler(device_type='cisco_ios_telnet', host=ip, username=user, password=passwd,
                                            secret=secret)
            connection.enable()
            hostname = connection.send_command("show run | inc hostname")
        except (NetMikoTimeoutException, TimeoutError):
            logging.error("[+] Failed: [IP]: %s (Reason: Connection Timedout)" % ip.strip('\n'))
            print("[+] Failed: [IP]: %s (Reason: Connection Timedout)" % ip.strip('\n'))
            continue
        except NetMikoAuthenticationException:
            logging.error("[+] Failed: [IP]: %s (Reason: Authentication Error)" % ip.strip('\n'))
            print("[+] Failed: [IP]: %s (Reason: Authentication Error)" % ip.strip('\n'))
            continue
        except ValueError as secreterror:
            if 'Failed to enter enable mode.' in str(secreterror):
                logging.error("[+] Failed: [IP]: %s (Reason: Wrong Secret)" % ip.strip('\n'))
                print("[+] Failed: [IP]: %s (Reason: Wrong Secret)" % ip.strip('\n'))
            else:
                logging.error("[+] Generic Error, check logs")
                print("[+] Generic Error, check logs")
            continue
        except SSHException:
            logging.error("[+] Failed: [IP]: %s (Reason: SSH Connection error)" % ip.strip('\n'))
            print("[+] Failed: [IP]: %s (Reason: SSH Connection error)" % ip.strip('\n'))
            continue
        except ConnectionRefusedError:
            logging.error("[+] Failed: [IP]: %s (Reason: Connection Refused)" % ip.strip('\n'))
            print("[+] Failed: [IP]: %s (Reason: Connection Refused)" % ip.strip('\n'))
            continue
        except ConnectionAbortedError:
            logging.error("[+] Failed: [IP]: %s (Reason: Software error)" % ip.strip('\n'))
            print("[+] Failed: [IP]: %s (Reason: Software Error)" % ip.strip('\n'))
            continue
        if hostname:
            print("[+] Connected %s:%s" % (hostname.split()[1], ip.strip('\n')))
            connection.send_config_from_file(config_file=config)
            if keyword:
                verifykeyword(keyword)
            connection.disconnect()


if __name__ == "__main__":
    main()

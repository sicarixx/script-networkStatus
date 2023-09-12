#!/usr/bin/python3
# Created by Sicarixx

import os, nmap

def welcome():
    welc = 'NMAP Port Scanner'
    info = '[INFO] Python script with NMAP to check the network status'
    os.system('clear')
    print(welc + '\n' + '*' * len(welc))
    print(info + '\n' + '-' * len(info))
    return

def getAddress():
    welcome()
    try:
        ipAddress = input('[+] Enter the IP Address: ')
        while(ipAddress == ''):
            ipAddress = input('[+] Please, enter the IP Address: ')
    except(KeyboardInterrupt):
        os.system('clear')
        welcome()
        print('[-] Interrupted by user!')
        exit()
    return ipAddress

def networkStatus():
    hosts = getAddress()
    print('-----------------------')
    print('[+] Scanning network...')
    print('-----------------------')
    nm = nmap.PortScanner()
    nm.scan(hosts + '/24', arguments='-n -sP -PE -PA21,23,80,3389')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    print('Host\t\t   Status')
    print('----\t\t   ------')
    for host, status in hosts_list:
        print(host + '\t : ' + status)
    return

if __name__ == '__main__':
    networkStatus()

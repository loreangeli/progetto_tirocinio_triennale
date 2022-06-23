'''
README: esegui antenna.py dalla directory principale del progetto
'''

from random import randrange
import random
import socket
import  time
import json
import os
import calendar


def num_random () :
    num = random.randint(0, 1000)
    return num

def generate_snapshot () :
    #timestamp
    gmt = time.gmtime()
    timestamp = calendar.timegm(gmt)
    
    snapshot = '{"timestamp": '+ str(timestamp) + ', "altitudine": '+str(num_random())+', "longitudine": '+str(num_random())+ '}'
    return snapshot

def asciitobin (string) :
    return bin(int.from_bytes(string.encode(), 'big'))

def bintoascii (bin) :
    n = int(bin, 2)
    bin = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()
    return bin


if __name__ == "__main__":
    #estrai dati da config.json
    config_file = json.load(open("config.json")) #estraggo config.json
    timesendsnapshot = config_file["timesendsnapshot"]

    #configurazione Client UDP
    MCAST_GRP = '224.1.1.1'
    MCAST_PORT = 5007
    bufferSize = 10240
    MULTICAST_TTL = 2

    #crea socket UDP per comunicare con il sistema mobile
    UDPClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    UDPClientSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
    
    print("simulazione ANTENNA_GPS: inizierà ad inviare pacchetti UDP alla 'stazione di riferimento' e al 'sistema mobile' !!")
    print(f"GENERATO UNO SNAPSHOT ogni {timesendsnapshot} secondi!!")
    print()
    

    while True:
        snapshot = generate_snapshot()
        snapshot_bin = asciitobin(snapshot) #snapshot in binario     
        print("generato snapshot:",snapshot)
        msgFromClient = snapshot_bin
        bytesToSend = msgFromClient.encode()

        #invia snapshot al sistema mobile e alla stazione di riferimento
        UDPClientSocket.sendto(bytesToSend, (MCAST_GRP, MCAST_PORT))
        print("snapshot INVIATO al sistema_mobile e alla stazione di riferimento")
        
        time.sleep(timesendsnapshot)
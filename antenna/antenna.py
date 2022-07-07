'''
README: esegui antenna.py dalla directory principale del progetto
'''

from random import randrange
import random
import socket
import  time
import json
import calendar
import sys
import signal

#SEGNALE
def signal_TERM(self, *args):
    msgFromClient = asciitobin("termina")
    bytesToSend = msgFromClient.encode()
    UDPClientSocket.sendto(bytesToSend, (MCAST_GRP, MCAST_PORT))
    print("inviato messaggio terminazione a SM e SR")
    #chiudi connessione UDP
    UDPClientSocket.close()
    sys.exit(0)

def num_random () :
    num = random.randint(0, 1000)
    return num

def generate_timestamp () :
    #timestamp
    gmt = time.gmtime()
    timestamp = calendar.timegm(gmt)
    
    snapshot = str(timestamp)
    return snapshot

def asciitobin (string) :
    return bin(int.from_bytes(string.encode(), 'big'))

def bintoascii (bin) :
    n = int(bin, 2)
    bin = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()
    return bin


if __name__ == "__main__":
    
    #registro i segnali da catturare
    signal.signal(signal.SIGTERM, signal_TERM)
    
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
    
    print("simulazione ANTENNA_GPS: iniziera' ad inviare pacchetti UDP alla 'stazione di riferimento' e al 'sistema mobile' !!")
    print(f"GENERATO UNO SNAPSHOT ogni {timesendsnapshot} secondi!!")
    

    while True:        
        timestamp = generate_timestamp()
        snapshot_bin = asciitobin(timestamp) #snapshot in binario     
        msgFromClient = snapshot_bin
        bytesToSend = msgFromClient.encode()

        #invia snapshot al sistema mobile e alla stazione di riferimento
        UDPClientSocket.sendto(bytesToSend, (MCAST_GRP, MCAST_PORT))
        print("<< GENERATO timestamp: " + timestamp + ", INVIATO al sistema_mobile e alla stazione di riferimento >>")
        
        time.sleep(timesendsnapshot)

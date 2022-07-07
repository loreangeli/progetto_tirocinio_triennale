import socket
from threading import Thread
import zipfile
import os
import struct
import threading
import utility
import signal
import sys


#SEGNALE
def signal_TERM(self, *args):
    pass
    
#configurazione Server UDP (comunicazione con antenna)
MCAST_GRP = '224.1.1.1'
MCAST_PORT = 5007
#configurazione Server TCP (comunicazione con sistema centrale)
host_sc = 'sistemacentrale'
port_sc = 12345
bufferSize = 10240


'''
    metodo che a partire dallo snapshot (stringa binaria) costruisce i due file:
    1. .zip contenente il file binario snapshot.bin (snapshot)
    2. file .JSON
'''
def create_files (binary_string) :
    binary_string = binary_string.encode()
    # id thread
    id = threading.get_native_id()
    
    # creo file binario dello snapshot
    snapshot_file = 'snapshot' + str(id) + '.bin'
    with open(snapshot_file,"wb") as f:
        f.write(binary_string)
    
    # creo file JSON
    metadati_file = "metadati" + str(id) + ".json"
    metadati = utility.bintoascii(binary_string)
    with open(metadati_file,"w") as f:
        f.write(metadati)
    
    # creo file .zip contenente: snapshot.bin
    zip_file = "packet" + str(id) + ".zip"
    with zipfile.ZipFile(zip_file, 'w', compression=zipfile.ZIP_DEFLATED) as packet_zip:
        packet_zip.write(snapshot_file, arcname="snapshot.bin")
    
    os.remove(snapshot_file) 
    return id
        
'''
    Metodo che fa due cose:
    1. rimane in ascolto dei pacchetti inviati da antenna
    2. invia i pacchetti ricevuti al sistema centrale tramite connessione TCP
'''
def server_UDP():
    # Creo connessione UDP
    UDPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    UDPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    UDPServerSocket.bind(('', MCAST_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
    UDPServerSocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    #Creo connessione client TCP con il sistema centrale per l'invio di .zip e JSON
    TCPclientsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    TCPclientsocket.connect((host_sc,port_sc))
    print("Connesso con TCP sistema centrale con host:"+str(host_sc)+", porta:"+str(port_sc))
    
    while True:
        #In ascolto di snapshot da antenna
        print("! in ascolto di snapshot da antenna !")
        msg = UDPServerSocket.recv(10240) #riceve il time-reference
        print("ricevuto snapshot: ",utility.bintoascii(msg))
        
        #gestisco SIGTERM
        if (utility.bintoascii(msg) == "termina"):
            print("messaggio terminazione ricevuto")
            TCPclientsocket.send(b"termina")
            #chiudi connessione TCP
            TCPclientsocket.close()
            #chiudi connessione UDP
            UDPServerSocket.close()
            return
        
        #ricostruisco i dati ricevuti dai satelliti
        message = '{"timestamp": '+ utility.bintoascii(msg) + ', "latitudine": "'+ utility.generate_latitudine() +'", "longitudine": "'+ utility.generate_longitudine() + '", "altitudine": ' + utility.generate_altitudine() + '}'
        print("dati di posizione:", message)
        
        #creo .zip e json
        message_bin = ''.join(format(i, '08b') for i in bytearray(message, encoding ='utf-8')) #trasformo la stringa in binario
        id = create_files(message_bin)
        
        #invio notifica: pronto ad inviare pacchetto
        TCPclientsocket.send(b"pronto")
        TCPclientsocket.recv(bufferSize)
        #invio 'packet.zip' a sistema centrale (via TCP)
        snapshot_file = "packet" + str(id) + ".zip"
        with open(snapshot_file, 'rb') as packet_to_send:
            data = packet_to_send.read()
        TCPclientsocket.sendall(data)
        
        #notifica ricezione pacchetto
        TCPclientsocket.recv(bufferSize)
        print("packet.zip INVIATO al sistema centrale")

        #invio 'metadati.json' a sistema centrale (via TCP)
        metadati_file = "metadati" + str(id) + ".json"
        with open(metadati_file, 'rb') as packet_to_send:
            data = packet_to_send.read()
            TCPclientsocket.sendall(data)
        print("metadati.json INVIATO al sistema centrale")  
        
        #elimina vari file
        os.remove(snapshot_file)
        os.remove(metadati_file)
     

if __name__ == "__main__":
    
    #registro i segnali da catturare
    signal.signal(signal.SIGTERM, signal_TERM)

    #Avvio thread
    thread_server_UDP = Thread(target=server_UDP)
    thread_server_UDP.start()
    thread_server_UDP.join()
    print("thread stazione di riferimento terminato correttamente")
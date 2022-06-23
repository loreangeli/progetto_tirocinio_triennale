import socket
from threading import Thread
import zipfile
import os
import struct
from datetime import datetime
import threading
import utility

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
    
    while(True):
        #In ascolto di snapshot da antenna
        print("? in ascolto di snapshot da antenna ?")
        message, address = UDPServerSocket.recvfrom(10240)
        print("-------")
        print ("! snapshot ricevuto da antenna! ")
        
        #creo .zip e json
        id = create_files(message)
        
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
    thread_server_UDP = Thread(target=server_UDP)
    thread_server_UDP.start()
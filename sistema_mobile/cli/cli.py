'''
    Terminale che consente l'interazione con il sistema mobile per richiedere la certificazione degli id ricevuti.
    Si crea una connessione TCP tra il sistemamobile.py e il CLI.
    Questo terminale si avvia da Docker andando nella CLI del container di cli e inserendo i seguenti comandi:
    /bin/bash
    python cli.py
'''
import time
import socket
import sys
import pickle


def help() :
    #suggerimenti
    print("stampa_lista _id: restituisce tutti gli id associati agli snapshot ricevuti dal sistema centrale")
    time.sleep(0.05)
    print("verifica_id id: verifica se l'id è stato certificato oppure no")
    time.sleep(0.05)
    print("help: comandi suggeriti")
    time.sleep(0.05)
    print("exit: chiudi terminale")
    time.sleep(0.05)

    

#configurazione Server TCP (comunicazione con cli)
host_cli = "sistemamobile"
port_cli = 12390
bufferSize = 10240

#Connessione client TCP con il sistema mobile per l'invio dello snapshot
TCPclientsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
TCPclientsocket.connect((host_cli,port_cli))
print("Connessione TCP con sistema mobile, host:"+str(host_cli)+", porta:"+str(port_cli))
print("digita help per i suggerimenti")


while True:
    
    msg = input(">>")
    if (msg == "help") :
        help()
    elif (msg == "exit") :
        TCPclientsocket.send("exit".encode())
        TCPclientsocket.close()
        sys.exit("Terminale cli chiuso")
    elif msg.startswith("verifica_id"):
        #estrai id
        msg_split = msg.split()
        print("msg_split[0]: ",msg_split[0])
        print("msg_split[1]: ",msg_split[1])
        
        if (len(msg_split)!=2):
            print("comando non riconosciuto, digita 'help' per i suggerimenti")
        elif (len(msg_split)==2):
            id = msg_split[1]
            #invia id da verificare al sistema mobile
            TCPclientsocket.send(id.encode())
            print("id inviato: ",id)
            #ricevo risposta (True/False) dal sistema mobile 
            data = TCPclientsocket.recv(bufferSize)
            print("ricevuto:",data.decode())
            ris = str(data.decode())
            print("ricevuto2:",data.decode())
            
            if (ris == "True") :
                print("Lo snapshot con id " + id + " è stato certificato correttamente")
            elif ris == "None":
                print("id inserito non corretto")
            else:
                print("Lo snapshot con id " + id + " non è stato certificato correttamente")
        else:
            print("comando non riconosciuto, digita 'help' per i suggerimenti")

    elif (msg == "stampa_lista_id"):
        #invia comando "stampa_lista_id" al sistema mobile
        TCPclientsocket.send("stampa_lista_id".encode())
        #ricevo lista
        data = TCPclientsocket.recv(bufferSize)
        lista = pickle.loads(data)
        print(lista)
    else:
        print('comando non riconosciuto, digita "help" per i suggerimenti')
        
        
        





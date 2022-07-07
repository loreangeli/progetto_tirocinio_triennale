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
import signal
import os


#SEGNALE
#variabile globale che viene impostata a False quando viene ricevuto un segnale SIGTERM
esegui = True
def signal_TERM(self, *args):
    global esegui
    esegui = False
    time.sleep(5)
    TCPclientsocket.send("termina".encode())
    print("termina cli")
    sys.exit(1)

def help() :
    #suggerimenti
    print("stampa_lista_id: restituisce tutti gli id associati agli snapshot ricevuti dal sistema centrale")
    time.sleep(0.05)
    print("verifica_id id: verifica se l'id è stato certificato oppure no")
    time.sleep(0.05)
    print("info_id id: restituisce le info di posizione per quell'id")
    time.sleep(0.05)
    print("help: comandi suggeriti")
    time.sleep(0.05)
    print("exit: chiudi terminale")
    time.sleep(0.05)
    print("clear: pulisci lo schermo")
    time.sleep(0.05)


if __name__ == "__main__":
    
    #registro i segnali da catturare
    signal.signal(signal.SIGTERM, signal_TERM)  

    #configurazione Server TCP (comunicazione con cli)
    host_cli = "sistemamobile"
    port_cli = 12390
    bufferSize = 10240

    #Connessione client TCP con il sistema mobile per l'invio dello snapshot
    TCPclientsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    TCPclientsocket.connect((host_cli,port_cli))
    print("Connessione TCP con sistema mobile, host:"+str(host_cli)+", porta:"+str(port_cli))
    print("digita help per i suggerimenti")


    while esegui:
        
        msg = input(">>")
        #comando help
        if (msg == "help") :
            help()
        #comando exit
        elif (msg == "exit") :
            TCPclientsocket.send("exit".encode())
            TCPclientsocket.close()
            sys.exit("Terminale cli chiuso")
        #comando info_id
        elif msg.startswith("info_id"):
            msg_split = msg.split()
            if len(msg_split) != 2:
                print("comando non riconosciuto, digita 'help' per i suggerimenti")
            else:
                #invio comando al sistema mobile
                TCPclientsocket.send("info_id".encode())
                #ricevo msg conferma ricezione
                TCPclientsocket.recv(bufferSize)
                
                #invia id da verificare al sistema mobile
                id = msg_split[1]
                TCPclientsocket.send(id.encode())
                print("id inviato: ",id)
                #ricevo info posizione dal sistema mobile 
                data = TCPclientsocket.recv(bufferSize)
                print("ricevuto:",data.decode())  
        #comando verifica_id
        elif msg.startswith("verifica_id"):
            #estrai id
            msg_split = msg.split()
            print("msg_split[0]: ",msg_split[0])
            print("msg_split[1]: ",msg_split[1])
            
            if len(msg_split)!=2:
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
        #comando stampa_lista_id
        elif (msg == "stampa_lista_id"):
            #invia comando "stampa_lista_id" al sistema mobile
            TCPclientsocket.send("stampa_lista_id".encode())
            #ricevo lista
            data = TCPclientsocket.recv(bufferSize)
            lista = pickle.loads(data)
            print(lista)        
        #comando clear
        elif(msg == "clear"):
            os.system('cls' if os.name == 'nt' else 'clear')
        #comando non riconosciuto
        else:
            print('comando non riconosciuto, digita "help" per i suggerimenti')
            
    #chiudi connessione
    TCPclientsocket.close()
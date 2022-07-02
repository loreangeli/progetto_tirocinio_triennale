#moduli vari
import socket
from threading import Thread
import zipfile
import hashlib
import struct
import os
import threading
import json
import pickle
#moduli algorand
from algosdk.future import transaction
from algosdk import account
from algosdk.v2client import algod
from algosdk.constants import min_txn_fee
#miei moduli
import utility


#configurazione Server UDP (comunicazione con antenna)
MCAST_GRP = '224.1.1.1'
MCAST_PORT = 5007

#configurazione Client TCP (comunicazione con sistema centrale)
host_sc = "sistemacentrale"
port_sc = 12370
bufferSize = 10240

#Comunicazione sistema centrale-cli
# configurazione Server TCP (comunicazione con cli)
host_cli = "sistemamobile"
port_cli = 12390
bufferSize = 10240
# configurazione Client TCP (comunicazione con sistema centrale per invio-ricezione id)
host_sc_sm= "sistemacentrale"
port_sc_sm = 12310
bufferSize = 10240

#lista dove salvo l'id degli snapshot ricevuto dal sistema centrale
list_id = []


'''
    Chiamata allo smart contract
'''
def call_app(client, private_key, index, app_args, accounts) :
    # dichiara il mittente della transazione
    sender = account.address_from_private_key(private_key)

    # imposta parametri suggeriti per la transazione
    params = client.suggested_params()
    params.fee = min_txn_fee
    params.flat_fee = True
     
    # crea transazione senza firma
    txn = transaction.ApplicationNoOpTxn(sender, params, index, app_args, accounts)
    # firma transazione
    signed_txn = txn.sign(private_key)
    tx_id = signed_txn.transaction.get_txid()

    # invia transazione
    try :
        client.send_transactions([signed_txn])
    except Exception as err:
        if (str(err).find("transaction already in ledger") != -1) :
            print("transazione gia' in blockchain")
        else :
            print(err)
            print("Suggerimento: potresti aver terminato il saldo nel conto")
        return
    
    # attendi conferma transazione
    try:
        transaction.wait_for_confirmation(client, tx_id, 4)
        print("TXID: " + tx_id + "-->" + app_args[0].decode())

    except Exception as err:
        print(err)
        return

 
'''
    Metodo per far fare opt-in allo smart contract al sistema mobile
'''
def opt_in(client, private_key, app_id, app_args, accounts):
    # define sender as creator
    sender = account.address_from_private_key(private_key)

    # get node suggested parameters
    params = client.suggested_params()
    params.fee = min_txn_fee
    params.flat_fee = True
    
    # create unsigned transaction
    txn = transaction.ApplicationOptInTxn(sender, params, app_id, app_args, accounts)

    # sign transaction
    signed_txn = txn.sign(private_key)
    tx_id = signed_txn.transaction.get_txid()

    # send transaction
    try:
        client.send_transactions([signed_txn])
        #print("opt-in eseguito correttamente")
    except Exception as err:
        if str(err).find("has already opted in to app") != -1 :
            print("opt-in gia' eseguito")
        else :
            print("[optin exception] ",err)    
        return

    # wait for confirmation
    try:
        transaction_response = transaction.wait_for_confirmation(client, tx_id, 5)
        print("TXID: ", tx_id)
        print("Result confirmed in round: {}".format(transaction_response['confirmed-round']))

    except Exception as err:
        print("[optin exception] ",err)
        return

    return

# metodo che a partire dallo snapshot (stringa binaria) costruisce i due file:
# 1. .zip contenente il file binario (snapshot)
# 2. file JSON
def create_files (binary_string) :
    binary_string = binary_string.encode()
    #id thread
    id =threading.get_native_id()
    
    #creo file binario dello snapshot
    snapshot_file = 'snapshot' + str(id) + '.bin'
    with open(snapshot_file,"wb") as f:
        f.write(binary_string)
    
    #creo file JSON
    metadati_file = "metadati" + str(id) + ".json"
    metadati = utility.bintoascii(binary_string)
    with open(metadati_file,"w") as f:
        f.write(metadati)
    
    #creo file .zip contenente: snapshot.bin
    zip_file = "packet" + str(id) + ".zip"
    with zipfile.ZipFile(zip_file, 'w', compression=zipfile.ZIP_DEFLATED) as packet_zip:
        packet_zip.write(snapshot_file, arcname="snapshot.bin")  

    os.remove(snapshot_file)
    return id    

'''
    metodo che fa due cose: 
    1. rimane in ascolto dei pacchetti inviati da antenna
    2. invia i pacchetti ricevuti al sistema centrale tramite connessione TCP
'''
def server_UDP():
    # Connessione UDP
    UDPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    UDPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind to address and ip
    UDPServerSocket.bind(('', MCAST_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
    UDPServerSocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print("server UDP connesso ad antenna")
    
    #Connessione client TCP con il sistema centrale per l'invio dello snapshot
    TCPclientsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    TCPclientsocket.connect((host_sc,port_sc))
    print("Connesso con TCP sistema centrale con host:"+str(host_sc)+", porta:"+str(port_sc))
    
    while(True):
        #In ascolto di snapshot da antenna
        print("? in ascolto di snapshot da antenna ?")
        msg = UDPServerSocket.recv(10240) #riceve il time-reference
        #ricostruisco i dati ricevuti dai satelliti
        message = '{"timestamp": '+ utility.bintoascii(msg) + ', "latitudine": "'+ utility.generate_latitudine() +'", "longitudine": "'+ utility.generate_longitudine() + '", "altitudine": ' + utility.generate_altitudine() + '}'
        print("dati di posizione:", message)
        
        print("-------")
        print ("! snapshot ricevuto da antenna! ")
        
        #creo .zip e json
        message_bin = ''.join(format(i, '08b') for i in bytearray(message, encoding ='utf-8')) #trasformo la stringa in binario
        id = create_files(message_bin)
        
        #invio notifica: pronto ad inviare pacchetto
        TCPclientsocket.send(b"pronto")
        TCPclientsocket.recv(bufferSize)
        
        #salvo hash(snapshot) su var.locale di sistema mobile
        snapshot = message
        print("stringa: ", message)
        hash_snapshot = hashlib.sha256(snapshot.encode())
        hash_snapshot_hex = hash_snapshot.hexdigest()
        print("lo snapshot: ", hash_snapshot_hex)
        app_args = ["insert_local_hash_snapshot_sm".encode(), hash_snapshot_hex.encode()]
        call_app(algod_client, sistema_mobile_privatekey, app_id,  app_args, None)

        #invio 'packet.zip' a sistema centrale (via TCP)
        snapshot_file = "packet" + str(id) + ".zip"
        with open(snapshot_file, 'rb') as packet_to_send:
            data = packet_to_send.read()
        TCPclientsocket.sendall(data)
        print("packet.zip INVIATO al sistema centrale")

        #notifica ricezione pacchetto
        TCPclientsocket.recv(bufferSize)
        
        #invio 'metadati.json' a sistema centrale (via TCP)
        metadati_file = "metadati" + str(id) + ".json"
        with open(metadati_file, 'rb') as packet_to_send:
            data = packet_to_send.read()
            TCPclientsocket.sendall(data)
        print("metadati.json INVIATO al sistema centrale")        
        
        # ricevi conferma ricezione
        msg = TCPclientsocket.recv(bufferSize)
        
        # invio account_address_sistema_mobile
        TCPclientsocket.send(sistema_mobile_address.encode('utf-8'))
        print("sistema_mobile_address INVIATO al sistema centrale")
        
        # ricevo id associato allo snapshot dal sistema centrale
        data = TCPclientsocket.recv(bufferSize)
        id_snapshot = data.decode()
        list_id.append(id_snapshot)
        
        # richiedo autenticazione al sistema centrale tramite id (richiesta autenticazione)
        TCPclientsocket.send(id_snapshot.encode('utf-8'))
        
        # ricevi risposta autenticazione dal sistema centrale
        risultato_autenticazione = TCPclientsocket.recv(bufferSize)
        if risultato_autenticazione.decode() == "True":
            print("Autenticazione id " + id_snapshot + " confermata")
        else :
            print("Autenticazione id " + id_snapshot + " negata")
        
        # elimina vari file
        os.remove(snapshot_file)
        os.remove(metadati_file)
  
'''
    Metodo per comunicare con cli
    Rimane in attesa di una connessione TCP da parte della cli.py, riceve l'id da certificare e lo inoltra al sistema centrale,
    riceve la risposta (True: certificazione corretta /False: certificazione non corretta) e la rimanda alla cli. 
'''  
def server_TCP() :
    # crea connessione TCP con la cli (lato server)
    TCPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPServerSocket.bind((host_cli, port_cli))

    # setta il socket in modalità ascolto
    TCPServerSocket.listen()

    #stabilisci connessione TCP con la cli
    c, addr = TCPServerSocket.accept() #addr è una tupla che contiene [ip, porta]
    print("Connesso con TCP cli con host:"+str(addr[0])+", porta:"+str(addr[1]))

    #crea connessione TCP con sistema centrale per l'invio dell'id da verificare e ricezione della risposta (True/False) (lato client)
    TCPclientsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    TCPclientsocket.connect((host_sc_sm,port_sc_sm))
    print("Connesso con TCP sistema centrale-cli con host:"+str(host_sc_sm)+", porta:"+str(port_sc_sm))

    while True:
        # ricevi msg da cli
        data = c.recv(bufferSize)
        #msg ricevuto: 'stampa_lista_id'
        if (data.decode() == "stampa_lista_id"):
            lista=pickle.dumps(list_id)
            c.sendall(lista)
        #msg ricevuto: 'exit'    
        elif data.decode() == "exit":
            c.close()
            c, addr = TCPServerSocket.accept() #addr è una tupla che contiene [ip, porta] 
        #msg ricevuto: id
        else:
            # invia id al sistema centrale
            TCPclientsocket.send(data)
            
            # ricevi risposta dal sistema centrale
            data = TCPclientsocket.recv(bufferSize)
            
            #invia risposta alla cli
            c.send(data)

        

if __name__ == "__main__":
    #estrai dati da info_algorand.json
    config_file = json.load(open("info_algorand.json"))
    sistema_mobile_address = config_file["sistema_mobile_address"]
    sistema_mobile_privatekey = config_file["sistema_mobile_privatekey"]
    sistema_mobile_passphrase = config_file["sistema_mobile_passphrase"]
    app_id = config_file["app_id"]
    
    #app id
    print("[app-id: "+ str(app_id) + " ]")

    #configurazione algodClient
    '''
    # tramite sandbox (alternativa 1)
    # user declared algod connection parameters. Node must have EnableDeveloperAPI set to true in its config
    algod_address = "http://localhost:4001"
    algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    algod_client = algod.AlgodClient(algod_token, algod_address) 
    '''
    # tramite purestake (alternativa 2)
    headers = {
    "X-API-Key": "L8NJ22dpve6TjszRmN16t6Zf5BMD0sypaZ8tWfW6",
    }
    algod_client = algod.AlgodClient("", "https://testnet-algorand.api.purestake.io/ps2", headers)

    #opt-in di sistema mobile con lo smart contract
    opt_in(algod_client, sistema_mobile_privatekey, app_id, None, None)
    
    #avvio server UDP (comunicazione con antenna)
    thread_server_UDP = Thread(target=server_UDP)
    thread_server_UDP.start()
    
    #avvio server TCP (comunicazione con cli)
    thread_server_TCP = Thread(target=server_TCP)
    thread_server_TCP.start()
    
    
    
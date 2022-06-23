#moduli algorand
from algosdk.v2client import algod
from algosdk import account
from algosdk.constants import min_txn_fee
from algosdk.future import transaction
#moduli varie
import socket
from threading import Thread, Lock
import hashlib
import zipfile
import time
import psycopg2
import sys, signal
import json
#miei moduli
import database_library
import utility

#configurazione Server TCP con Sistema Mobile
host_sm = "sistemacentrale"
port_sm = 12370
bufferSize = 10240
#configurazione Server TCP con Stazione di Riferimento
host_sr = 'sistemacentrale'
port_sr = 12345

#SEGNALE
def signal_TERM(self, *args):
    sys.exit("segnale SIGTERM!")

#LOCK
'''
    Contatore con lock (per risolvere la race condition).
    Classe usata per associare un id univoco ad ogni file .zip e .json ricevuto dal sistema mobile
    e dalla stazione di riferimento.
'''
class Counter:
    def __init__(self):
        self.value = 0
        self.lock = Lock()

    def increase(self):
        self.lock.acquire()

        current_value = self.value
        current_value += 1

        self.value = current_value

        self.lock.release()
        return self.value
    
#database
'''
    Lock per inserimento e rimozione nel database del record <id, check> evitando
    la race condition.
'''
lock_database = Lock()


''' 
    Metodo che chiama lo smart contract. 
    Gli argomenti del metodo sono i seguenti:
    client: oggetto di tipo AlgodClient
    private_key: chiave privata del mittente che vuole effettuare la chiamata allo smart contract
    index: indice dell'applicazione dello smart contract
    app_args: argomenti passati nella chiamata
    accounts: account passati nella chiamata
    note: campo nota
'''
def call_app(client, private_key, index, app_args, accounts, note) :
    # imposta il mittente della transazione
    sender = account.address_from_private_key(private_key)

    # imposta parametri per la transazione
    params = client.suggested_params()
    params.fee = min_txn_fee
    params.flat_fee = True
     
    # crea transazione non firmata
    txn = transaction.ApplicationNoOpTxn(sender, params, index, app_args, accounts, None, None, note)
    # firma transazione
    signed_txn = txn.sign(private_key)
    tx_id = signed_txn.transaction.get_txid()

    # invia transazione
    try :
        client.send_transactions([signed_txn])
    except Exception as err:
        if (str(err).find("transaction already in ledger") != -1) :
            print("transazione già in blockchain")
        else :
            print(err)
            print("Suggerimento: potresti aver terminato il saldo nel conto")
        return
    
    # attesa conferma della transazione
    try:
        transaction.wait_for_confirmation(client, tx_id, 4)
        print("TXID: " + tx_id + ", " + app_args[0].decode())

    except Exception as err:
        print(err)
        return

#THREAD
'''
    Thread che serve per la comunicazione con il sistema mobile.
    Gli argomenti del metodo sono i seguenti:
    c: socket per poter comunicare via TCP con il sistema mobile
    algod_client: oggetto di tipo AlgodClient usato per fare la app_call allo smart contract
    cursor: usato per Postgres
    conn: usato per Postgres
    cont_sm: id del sistema mobile (serve per identificare univocamente ogni sistema mobile collegato)
    counter: serve per associare ad ogni file .zip e .json un id
'''
def thread_sm (c, algod_client, cursor, conn, cont_sm,counter) :  
    
    # ciclo infinito che rimane in attesa dei file .zip e e.json dal sistema mobile
    while True :   
        # Vale True se c'è stato un problema nella chiamata 'compare_hash'
        errore_compare_hash = False
        # incremento id di .zip e .json
        id_sm = counter.increase()
        
        # ricevi notifica: sistema mobile pronto a ricevere .zip
        c.recv(bufferSize)
        c.send(b"pronto")
        
        # ricevo packet_sm.zip
        dir_zip_sm = "packet_sm" + str(id_sm) + ".zip" 
        filetodown = open(dir_zip_sm,'wb')
        data = c.recv(bufferSize)
        filetodown.write(data)
        filetodown.close()
        print("packet_sm" + str(id_sm) + ".zip RICEVUTO da  sistema mobile "+ str(id_sm))

        # invio notifica ricezione packet_sm.zip
        c.send(b"ok")

        # ricevo metadati_sm.json
        dir_json_sm = "metadati_sm" + str(id_sm) + ".json" 
        filetodown_2 = open(dir_json_sm,'wb')
        data = c.recv(bufferSize)
        #print("metadati_sm" + str(id_sm) + ".json" + " text: "+ data.decode())
        filetodown_2.write(data)
        filetodown_2.close()
        print("metadati_sm" + str(id_sm) + ".json" + " RICEVUTO da sistema mobile "+ str(cont_sm))
        
        # invio conferma ricezione metadati.json
        c.send(b"done")
        
        # ricevo account_address_sistema_mobile
        msg = c.recv(bufferSize)
        account_address_sistema_mobile=msg.decode('utf-8')
        print("sistema_mobile_address RICEVUTO dal sistema mobile " + str(cont_sm))

        # estrai 'snapshot.bin' da packet_sm.zip e calcola l'hash
        archive = zipfile.ZipFile(dir_zip_sm, 'r')
        snapshot = archive.read('snapshot.bin')
        hash_snapshot = hashlib.sha256(snapshot)
        hash_snapshot_sm_hex = hash_snapshot.hexdigest()
        
        # calcolo id (cioè l'hash del file .zip ricevuto dal sistema mobile)
        sha256_hash = hashlib.sha256()
        with open(dir_zip_sm,"rb") as f:
            #leggi e aggiorna il valore della stringa hash in blocchi di 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            id_snapshot = sha256_hash.hexdigest()
        
        #qua dovrei cercare lo 'snapshot.bin' della stazione di riferimento
        #corrispondente a quello ricevuto dal sistema mobile e calcolare il suo hash
        #attendi che packet_sr.zip sia stato scaricato prima di calcolarci l'hash 
        # archive = zipfile.ZipFile(dir_zip_sr, 'r')
        # snapshot = archive.read('snapshot.bin')
        # hash_snapshot = hashlib.sha256(snapshot)
        # hash_snapshot_sr_hex = hash_snapshot.hexdigest()
        
        # fake hash del file 'snapshot.bin' contenuto nel .zip ricevuto dalla sistema di riferimento
        hash_snapshot_sr_hex = "fake_snapshot"
        
        # controllo che lo snapshot ricevuto dal sistema mobile tramite connessione TCP non sia stato alterato/modificato
        # questa operazione la posso fare chiamando 'compare_hash'
        app_args = ["compare_hash".encode(), hash_snapshot_sm_hex.encode()]
        accounts = [account_address_sistema_mobile]
        try :
            #risultato_autenticazione viene settato a True se non ci sono stati errori nella chiamata 'compare_hash'
            risultato_autenticazione = not errore_compare_hash
            #chiamo il metodo 'compare_hash' dello smart contract
            call_app(algod_client, sistema_centrale_privatekey, app_id, app_args, accounts, None)
        except Exception as err :
            errore_compare_hash = True
            risultato_autenticazione = not errore_compare_hash
            #inserisci record <id, risultato> nel database
            database_library.add_snapshot(cursor, conn, id_snapshot, risultato_autenticazione, lock_database)
            print("lo snapshot potrebbe essere stato alterato oppure c'è stato un errore differente")
            print(err)
        if (errore_compare_hash == False) :
            #chiamo metodo smart contract 'validate_snapshot'
            app_args=["validate_snapshot".encode()]
            note = "id: " + id_snapshot + ", hash_snapshot_sm: " + hash_snapshot_sm_hex + ", hash_snapshot_sr: " + hash_snapshot_sr_hex
            call_app(algod_client, sistema_centrale_privatekey, app_id, app_args, None, note.encode())
            #inserisci record <id, risultato> nel database
            database_library.add_snapshot(cursor, conn, id_snapshot, risultato_autenticazione, lock_database)
           
        #invio id (hash del contenuto di snapshot.bin ricevuto dal sistema mobile) al sistema mobile
        #print("id_snapshot (snapshot.bin): ",id_snapshot)
        c.send(id_snapshot.encode('utf-8'))
            
        #ricevo id per procedere all'autenticazione dello snapshot (richiesta autenticazione)
        msg = c.recv(bufferSize)
        id_receive = msg.decode('utf-8')
        #elimina il record <id, risultato> dal database dopo che il sistema mobile ha richiesto l'autenticazione dello snapshot
        database_library.delete_snapshot(cursor, conn, id_receive, lock_database)
        
        #invia risposta autenticazione al sistema mobile
        c.send(str(risultato_autenticazione).encode('utf-8'))
              
'''
    Server TCP che comunica con il sistema mobile.
    Gli argomenti passati sono i seguenti:
    cursor: usato per Postgres
    conn: usato per Postgres
    counter: serve per associare ad ogni .zip e .json un id
'''
def server_sm (cursor, conn, counter) :
    cont_sm = 0 #associa un id a ogni sistema mobile che si collega
    
    # crea connessione TCP con il sistema mobile
    TCPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPServerSocket.bind((host_sm, port_sm))
    TCPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # setta il socket in modalità ascolto
    TCPServerSocket.listen()

    # rimane in ascolto di nuove connessioni con il sistema mobile e se ne arriva una avvia un thread per gestirla
    while (True) :
        cont_sm = cont_sm + 1
        # stabilisci connessione TCP con il sistema mobile
        c, addr = TCPServerSocket.accept() #addr è una tupla che contiene [ip, porta]
        thread_server_sm = Thread(target=thread_sm, args=(c, algod_client, cursor, conn, cont_sm,counter))
        print("Connessione TCP con sistema mobile, host:"+str(addr[0])+", porta:"+str(addr[1]))
        thread_server_sm.start()
         
    c.close()

'''
    Thread che serve per la comunicazione con la stazione di riferimento
    Gli argomenti del metodo sono i seguenti:
    c: socket per poter comunicare via TCP con la stazione di riferimento
    cont_sr: id della stazione di riferimento (serve per identificare univocamente ogni stazione di riferimento collegata)
    counter: serve per associare ad ogni file .zip e .json un id
'''
def thread_sr(c, cont_sr,counter) :
    
    # ciclo infinito che rimane in attesa dei file .zip e e.json dal sistema mobile
    while True:
        # incremento id di .zip e .json
        id_sr = counter.increase()
        
        # ricevi notifica: stazione di riferimento pronta a ricevere .zip
        c.recv(bufferSize)
        c.send(b"pronto")
       
        # ricevo packet_sr.zip
        dir_zip_sr = "packet_sr" + str(id_sr) + ".zip" 
        filetodown = open(dir_zip_sr,'wb')
        data = c.recv(bufferSize)
        filetodown.write(data)
        filetodown.close()
        print("packet_sr" + str(id_sr) + ".zip" + " RICEVUTO dalla stazione di riferimento " + str(cont_sr))

        # invio conferma ricezione
        c.send(b"done")
        
        # ricevo metadati_sr.json
        dir_json_sr = "metadati_sr" + str(id_sr) + ".json" 
        filetodown_2 = open(dir_json_sr,'wb')
        data = c.recv(bufferSize)
        print("metadati_sr" + str(id_sr) + ".json" + " text: "+ data.decode())
        filetodown_2.write(data)
        filetodown_2.close()
        print("metadati_sr" + str(id_sr) + ".json" + " RICEVUTO dalla stazione di riferimento " + str(cont_sr)) 

'''
    Server TCP che comunica con la stazione di riferimento
    Gli argomenti passati sono i seguenti:
    counter: serve per associare ad ogni .zip e .json un id
'''
def server_sr (counter) :
    cont_sr = 0 #associa un id a ogni sistema mobile che si collega
    
    # crea connessione TCP con la stazione di riferimento
    TCPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPServerSocket.bind((host_sr, port_sr))

    # setta il socket in modalità ascolto
    TCPServerSocket.listen()

    # rimane in ascolto di nuove connessioni con il sistema mobile e se ne arriva una avvia un thread per gestirla
    while True :
        cont_sr = cont_sr + 1
        #stabilisci connessione TCP con la stazione di riferimento
        c, addr = TCPServerSocket.accept() #addr è una tupla che contiene [ip, porta]
        print("Connesso con TCP stazione di riferimento con host:"+str(addr[0])+", porta:"+str(addr[1]))
        thread_server_sr = Thread(target = thread_sr, args=(c, cont_sr,counter))
        thread_server_sr.start()

    c.close()


if __name__ == "__main__":
    #estrai dati da info_algorand.json
    config_file = json.load(open("info_algorand.json"))
    sistema_centrale_address = config_file["sistema_centrale_address"]
    sistema_centrale_privatekey = config_file["sistema_centrale_privatekey"]
    sistema_centrale_passphrase = config_file["sistema_centrale_passphrase"]
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

    #SEGNALE
    signal.signal(signal.SIGTERM, signal_TERM)
    
    #configurazione database PostgreSQL
    conn = psycopg2.connect(user="postgres", password="postgres", database="postgres", host="db", port="5432")
    if (database_library.DEBUG == True): print("Database PostgreSQL connesso.")
    conn.autocommit = True
    cursor = conn.cursor()
    database_library.create_database(cursor, 'SNAPSHOT_LIST')
    database_library.create_table_snapshot_list (cursor, conn)
    # delete_table(cursor, conn, 'SNAPSHOT_LIST')
    # delete_database(cursor, 'SNAPSHOT_LIST')

    #inizializzo i contatori
    counter = Counter() #sistema mobile
    counter2 = Counter() #stazione di riferimento
    
    #server per comunicare con sistema mobile
    thread_server_sm = Thread(target=server_sm, args=(cursor,conn, counter))
    thread_server_sm.start()
    #server per comunicare con la stazione di riferimento
    thread_server_sr = Thread(target=server_sr,args=(counter2,))
    thread_server_sr.start()
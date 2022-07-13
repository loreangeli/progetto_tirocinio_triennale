#moduli algorand
from algosdk.v2client import algod
from algosdk import account
from algosdk.constants import min_txn_fee
from algosdk.future import transaction
#moduli varie
import os
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

#Impostata a True algod funziona tramite Sandbox
#Impostata a False algod funziona tramite Purestake
SANDBOX = False

#configurazione Server TCP con Sistema Mobile (ricezione .zip e .JSON)
host_sm = "sistemacentrale"
port_sm = 12370
bufferSize = 10240
#configurazione Server TCP con Stazione di Riferimento (ricezione .zip e .JSON)
host_sr = 'sistemacentrale'
port_sr = 12345

# configurazione Server TCP (comunicazione con sistema mobile per invio-ricezione id)
host_sc_sm= "sistemacentrale"
port_sc_sm = 12310
bufferSize = 10240

#SEGNALE
#variabile globale che viene impostata a False quando viene ricevuto un segnale SIGTERM
esegui = True
def signal_TERM(self, *args):
    global esegui
    esegui = False
    time.sleep(7)
    sys.exit(0)

#LOCK
'''
    Contatore con lock (per risolvere la race condition).
    Classe usata per associare un id univoco ad ogni file .zip e .json ricevuto dal sistema mobile
    e alla stazione di riferimento.
'''
class Counter:
    def __init__(self):
        self.value = 0
        #controllo se ci sono già file .zip (esempio: packet_sm12.zip -> devo estrarre il numero 12) salvati e guardo a che numero sono arrivato
        max = 0
        files = os.listdir("/data/")
        for stringa in files:
            if stringa.find(".zip") != -1 :
                stringa = stringa.replace(".zip", "")
                if stringa.find("packet_sm") != -1 :
                    stringa = stringa.replace("packet_sm", "")
                elif stringa.find("packet_sr") != -1 :
                    stringa = stringa.replace("packet_sr", "")
                #estraggo numero
                id = int(stringa)
                if id > max :
                    max = id
            self.value = max + 1
        self.lock = Lock()

    def increase(self):
        self.lock.acquire()

        current_value = self.value
        current_value += 1

        self.value = current_value

        self.lock.release()
        return self.value
    
'''
    Contatore con lock usato per il sistema mobile e la stazione di riferimento.
    Dobbiamo far si che prima di controllare se gli snapshot ricevuti sono corretti siano arrivati tutti i file .zip e .json.
    Spiegazione: imposto cont a 0 all'inizio, non appena il sistema mobile e la stazione di ricevimento iniziano a ricevere fanno entrambi cont ++,
    quando finiscono fanno cont--.  thread del sistema mobile si mettono in attesa che cont sia a 0 prima di poter andare a fare le varie operazioni
    di confronto degli snapshot.
'''
class Counter_lock:
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
    
    def decrease(self):
        self.lock.acquire()
        
        current_value = self.value
        current_value -= 1
        
        self.value = current_value
        
        self.lock.release()
        return self.value
        
    def get_counter(self):
        return self.value 

#lock per inserimento dei record nel file 'object_storage.json' e 'metadati.json'
lock_json = Lock()


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
def call_app(client, private_key, index, app_args, accounts, note, cont_sm) :
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
        print("["+ str(cont_sm) + "] " + "TXID: " + tx_id + ", " + app_args[0].decode())

    except Exception as err:
        print(err)
        return

#THREAD
'''
    Thread che serve per la comunicazione con il sistema mobile. Viene avviato un thread di questo tipo per ogni sistema mobile avviato.
    Gli argomenti del metodo sono i seguenti:
    c: socket per poter comunicare via TCP con il sistema mobile
    algod_client: oggetto di tipo AlgodClient usato per fare la app_call allo smart contract
    cursor: usato per Postgres
    conn: usato per Postgres
    cont_sm: id del sistema mobile (serve per identificare univocamente ogni sistema mobile collegato)
    counter: serve per associare ad ogni file .zip e .json un id
'''
def thread_sm (c, algod_client, cursor, conn, cont_sm,counter, counter_lock) : 
    
    #variabile globale usata per certificare che lo snapshot ricevuto dal sistema mobile è 
    #equivalente a quello delle stazioni di riferimento (nota che tecnicamente non sono uguali
    # ma vengono allineati, nel progetto non teniamo conto di questo!)
    certificazione = True #vale True se il confronto degli snapshot va a buon fine

    # ciclo infinito che rimane in attesa dei file .zip e e.json dal sistema mobile
    while True:   
        certificazione = True
        risultato_autenticazione = True
        # vale False se c'è stato un problema nella chiamata 'compare_hash'
        correct_compare_hash = True
        
        # incremento id di .zip e .json
        id_sm = counter.increase()
        
        # ricevi notifica: sistema mobile pronto a ricevere .zip
        msg = c.recv(bufferSize)
        
        #ricevuto SIGTERM
        if (msg.decode() == "termina") :
            c.close()
            return
        
        c.send(b"pronto")
        
        counter_lock.increase()
                
        # ricevo packet_sm.zip
        dir_zip_sm = "/data/" + "packet_sm" + str(id_sm) + ".zip" 
        filetodown = open(dir_zip_sm,'wb')
        data = c.recv(bufferSize)
        filetodown.write(data)
        filetodown.close()
        msg_1 = "packet_sm" + str(id_sm) + ".zip RICEVUTO da  sistema mobile "+ str(cont_sm)

        # invio notifica ricezione packet_sm.zip
        c.send(b"ok")

        # ricevo metadati_sm.json
        dir_json_sm = "/data/" + "metadati_sm" + str(id_sm) + ".json" 
        filetodown_2 = open(dir_json_sm,'wb')
        data = c.recv(bufferSize)
        #print("metadati_sm" + str(id_sm) + ".json" + " text: "+ data.decode())
        filetodown_2.write(data)
        filetodown_2.close()
        msg_2 = "metadati_sm" + str(id_sm) + ".json" + " RICEVUTO da sistema mobile "+ str(cont_sm)
        
        print(msg_1 + " " + msg_2)
        
        # invio conferma ricezione metadati.json
        c.send(b"done")
        
        counter_lock.decrease()
        
        # ricevo account_address_sistema_mobile
        msg = c.recv(bufferSize)
        account_address_sistema_mobile=msg.decode('utf-8')
        print("sistema_mobile_address RICEVUTO dal sistema mobile " + str(cont_sm))

            
        # estrai 'snapshot.bin' da packet_sm.zip e calcola l'hash
        archive = zipfile.ZipFile(dir_zip_sm, 'r')
        snapshot = archive.read('snapshot.bin')
        snapshot = utility.bintoascii(snapshot)
        # print("contenuto 'snapshot.bin' di sm " + str(cont_sm) + ": " + str(snapshot))
        hash_snapshot = hashlib.sha256(snapshot.encode())
        hash_snapshot_sm_hex = hash_snapshot.hexdigest()
        
        # calcolo id (cioè l'hash del file .zip ricevuto dal sistema mobile)
        sha256_hash = hashlib.sha256()
        with open(dir_zip_sm,"rb") as f:
            #leggi e aggiorna il valore della stringa hash in blocchi di 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            id_snapshot = sha256_hash.hexdigest()
        
        lock_json.acquire()
        #aggiungo record a 'object_storage.json'
        with open('/data/object_storage.json', 'r') as jsonfile:
            dictionary_object_storage = json.load(jsonfile)
        record = {id_snapshot:dir_zip_sm}
        dictionary_object_storage.update(record) #appendi il record nel file .json
        with open('/data/object_storage.json', 'w') as outfile: #aggiungo record ad 'object_storage.json'
            json.dump(dictionary_object_storage, outfile)
        
        #aggiungo record a 'metadati.json'
        f_metadati = open('/data/metadati.json',) 
        dictionary_metadati = json.load(f_metadati)
        record = {id_snapshot:dir_json_sm}
        dictionary_metadati.update(record) #appendi il record nel file .json
        with open('/data/metadati.json', 'w') as outfile2: #aggiungo record ad 'object_storage.json'
            json.dump(dictionary_metadati, outfile2)        
        lock_json.release()
        
        #attendo che tutti i file .json e .zip dei sistemi mobili e dalle stazioni di riferimento siano arrivati
        while counter_lock.get_counter() != 0 :
            pass
        
        #CONFRONTO DEGLI SNAPSHOT (per chiarimenti guarda la figura 'Ricerca snapshot da id')                 
        #estraggo il percorso del file .zip associato all'id 'id_snapshot' estraendolo dal file 'object_storage.json'
        percorsofile_zip = dictionary_object_storage[id_snapshot]
        #estraggo 'snapshot.bin' dal file .zip
        archive = zipfile.ZipFile(percorsofile_zip, 'r')
        snapshot = archive.read('snapshot.bin')
        #estraggo il percorso del file dei metadati di id_snapshot sfruttando 'metadati.json'
        percorsofile_json = dictionary_metadati[id_snapshot]
        #estraggo il campo timestamp
        with open(percorsofile_json) as jsonfile: 
            dict_tmp = json.load(jsonfile) #ritorna l'oggetto JSON come dizionario
        timestamp = dict_tmp['timestamp']
        ''' 
        scorro ciascun file .json dei metadati: controllo che abbia il solito timestamp di 'timestamp', se 
        la condizione vale ricerco il file .zip associato a quel file .json. Come?
        andando nel file 'metadati.json' e prendendo il campo id associato a quel
        file dei metadati. Con il campo id trovo il file .zip sfruttando il file
        'object_storage.json' e confronto quello snapshot con quello della variabile
        chiamata 'snapshot'. 
        '''
        #scorro i json dei metadati
        files = os.listdir("/data/")
        for file in files:
            if file.find("metadati_") != -1:
                #estraggo il timestamp dal file
                with open("/data/" + file) as jsonfile: 
                    data2 = json.load(jsonfile) #ritorna l'oggetto JSON come dizionario
                timestamp_tmp = data2['timestamp']
                #controllo che abbia il solito timestamp di quello che mi interessa
                if (timestamp == timestamp_tmp) :
                    ## Ricerco il file .zip associato a quel file dei metadati
                    #vado nel file 'metadati.json' e prendo il campo id associato a quel file dei metadati
                    for id in dictionary_metadati:
                        if dictionary_metadati[id] == ("/data/" + file): #se vale True: id è l'id che volevamo
                            #vado nel file 'object_storage.json' e tramite id prendo il campo contentente il .zip
                            file_zip_trovato = dictionary_object_storage[id]
                            #estraggo lo snapshot
                            archive = zipfile.ZipFile(file_zip_trovato, 'r')
                            snapshot_tmp = archive.read('snapshot.bin')  
                            #confronto lo snapshot appena trovato con quello della variabile chiamata snapshot
                            if (snapshot == snapshot_tmp) :
                                pass
                            else :
                                certificazione = False
                                      
        # controllo che lo snapshot ricevuto dal sistema mobile tramite connessione TCP non sia stato alterato/modificato
        # questa operazione la posso fare chiamando 'compare_hash'
        app_args = ["compare_hash".encode(), hash_snapshot_sm_hex.encode()]
        accounts = [account_address_sistema_mobile]
        try :
            #chiamo il metodo 'compare_hash' dello smart contract
            call_app(algod_client, sistema_centrale_privatekey, app_id, app_args, accounts, None, cont_sm)
        except Exception as err :
            correct_compare_hash = False
            risultato_autenticazione = correct_compare_hash
            #inserisci record <id, risultato> nel database
            database_library.add_snapshot(cursor, conn, id_snapshot, risultato_autenticazione, lock_database)
            print("lo snapshot potrebbe essere stato alterato oppure c'e' stato un errore differente")
            print(err)
        if (correct_compare_hash == True and certificazione == True) : #è andato tutto bene -> valido posizione
            #chiamo metodo smart contract 'validate_snapshot'
            app_args=["validate_snapshot".encode()]
            #note = "id: " + id_snapshot + ", hash_snapshot_sm: " + hash_snapshot_sm_hex + ", hash_snapshot_sr: " + hash_snapshot_sr_hex
            note = "id: " + id_snapshot + ", hash_snapshot_sm: " + hash_snapshot_sm_hex
            call_app(algod_client, sistema_centrale_privatekey, app_id, app_args, None, note.encode(), cont_sm)
            #inserisci record <id, risultato> nel database postgres
            database_library.add_snapshot(cursor, conn, id_snapshot, risultato_autenticazione, lock_database)
            # database_library.print_table(conn)
        if certificazione == False:
            print("errore, lo snapshot potrebbe essere stato alterato")
            
        #invio id dello snapshot (cioè l'hash del file .zip ricevuto dal sistema mobile) al sistema mobile
        #print("id_snapshot (snapshot.bin): ",id_snapshot)
        c.send(id_snapshot.encode('utf-8'))
            
        #ricevo id per procedere all'autenticazione dello snapshot (richiesta autenticazione)
        msg = c.recv(bufferSize)
        id_receive = msg.decode('utf-8')
        #elimina il record <id, risultato> dal database dopo che il sistema mobile ha richiesto l'autenticazione dello snapshot
        # database_library.delete_snapshot(cursor, conn, id_receive, lock_database)
        
        #invia risposta autenticazione al sistema mobile
        c.send(str(risultato_autenticazione).encode('utf-8'))
    
    
'''
    Crea una comunicazione con il sistema mobile per la certificazione gli snapshot. Questo thread rimane in ascolto di 
    id da verificare al sistema mobile e inoltra la risposta. Il sistema mobile invierà poi il risultato al cli.
'''
def thread_sm_cli(c, cursor, conn) :
     while True:
        # ricevi id dal sistema mobile
        data = c.recv(bufferSize)
        print("data: ",data.decode())
        #gestione SIGTERM
        if (data.decode() == "termina"):
            c.close()
            print("chiudi thread_sm_cli")
            return
         
        if data.decode() == "info_id":
            #invio conferma ricezione "info_id"
            c.send("ok".encode())
            #ricevo id
            data = c.recv(bufferSize)
            id = str(data.decode())
            print("id:", id)
            '''estraggo info posizione dell'id, cerca il nome del file metadati relativo a quell'id
            nel file metadati.json. '''
            # leggo il file
            with open('/data/metadati.json', 'r') as jsonfile:
                dictionary_object_storage = json.load(jsonfile)
            percorsofile_json = dictionary_object_storage[id]
            print("percorsofile_json: ", percorsofile_json)
            #leggo il json ed estraggo i dati di posizione
            with open(percorsofile_json) as jsonfile: 
                data = json.load(jsonfile) #ritorna l'oggetto JSON come dizionario
                print("estratto:", str(data))
            #invio i dati di posizione al sistema mobile
            c.sendall(str(data).encode())
        else :  
            id = str(data.decode())
            #controlla nel database il risultato del record <id, risultato>
            record = database_library.search_snapshot(cursor, conn, id, lock_database)
            if record == "None": #id non trovato tra i record nel database
                # invia risposta (se l'id è stato certificato correttamente oppure no)
                c.send("None".encode())
            else : #id trovato nel database
                risultato = str(record[1])
                # invia risposta (se l'id è stato certificato correttamente oppure no)
                c.sendall(risultato.encode())


'''
    Thread che serve per la comunicazione con la stazione di riferimento
    Gli argomenti del metodo sono i seguenti:
    c: socket per poter comunicare via TCP con la stazione di riferimento
    cont_sr: id della stazione di riferimento (serve per identificare univocamente ogni stazione di riferimento collegata)
    counter: serve per associare ad ogni file .zip e .json un id
'''
def thread_sr(c, cont_sr,counter, counter_lock) :
    
    # ciclo infinito che rimane in attesa dei file .zip e e.json dal sistema mobile
    while True:
        # incremento id di .zip e .json
        id_sr = counter.increase()

        # ricevi notifica: stazione di riferimento pronta a ricevere .zip
        msg = c.recv(bufferSize)
            
        #ricevuto SIGTERM
        if (msg.decode() == "termina") :
            # print("ricevuto termina per sr!")
            c.close()
            return
            
        c.send(b"pronto")
    
        counter_lock.increase()
            
        # ricevo packet_sr.zip
        dir_zip_sr = "/data/" + "packet_sr" + str(id_sr) + ".zip" 
        filetodown = open(dir_zip_sr,'wb')
        data = c.recv(bufferSize)
        filetodown.write(data)
        filetodown.close()
        msg_1 = "packet_sr" + str(id_sr) + ".zip" + " RICEVUTO dalla stazione di riferimento " + str(cont_sr)


        # estrai 'snapshot.bin' da packet_sr.zip e stampa il contenuto
        archive = zipfile.ZipFile(dir_zip_sr, 'r')
        snapshot = archive.read('snapshot.bin')
        snapshot = utility.bintoascii(snapshot)
        # print("contenuto 'snapshot.bin' di sr " + str(cont_sr) + ": " + str(snapshot))
        
        
        # invio conferma ricezione
        c.send(b"done")
        
        # ricevo metadati_sr.json
        dir_json_sr = "/data/" + "metadati_sr" + str(id_sr) + ".json" 
        filetodown_2 = open(dir_json_sr,'wb')
        data = c.recv(bufferSize)
        # print("metadati_sr" + str(id_sr) + ".json" + " text: "+ data.decode())
        filetodown_2.write(data)
        filetodown_2.close()
        msg_2 = "metadati_sr" + str(id_sr) + ".json" + " RICEVUTO dalla stazione di riferimento " + str(cont_sr)
        
        print(msg_1 + " " + msg_2)
        
        # calcolo id (cioè l'hash del file .zip ricevuto dal sistema mobile)
        sha256_hash = hashlib.sha256()
        with open(dir_zip_sr,"rb") as f:
            #leggi e aggiorna il valore della stringa hash in blocchi di 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            id_snapshot = sha256_hash.hexdigest()
        
        lock_json.acquire()      
        #aggiungo record a 'object_storage.json'
        f_object_storage = open('/data/object_storage.json',) 
        dictionary_object_storage = json.load(f_object_storage)
        # print("contenuto 'object_storage.json': ",dictionary_object_storage)
        record = {id_snapshot:dir_zip_sr}
        dictionary_object_storage.update(record) #appendi il record nel file json
        with open('/data/object_storage.json', 'w') as outfile: #aggiungo record ad 'object_storage.json'
            json.dump(dictionary_object_storage, outfile)
        
        #aggiungo record a 'metadati.json'
        f_metadati = open('/data/metadati.json',) 
        dictionary_metadati = json.load(f_metadati)
        # print("contenuto 'metadati.json': ",dictionary_metadati)
        record2 = {id_snapshot:dir_json_sr}
        dictionary_metadati.update(record2) #appendi il record nel file json
        with open('/data/metadati.json', 'w') as outfile2: #aggiungo record ad 'object_storage.json'
            json.dump(dictionary_metadati, outfile2) 
        lock_json.release()       
           
        counter_lock.decrease()


'''
    Server che rimane in ascolto di nuove connessioni TCP con i sistemi mobili, non appena
    viene aperta una nuova connessione da un sistema mobile viene creato un thread che la gestisce.
    Questo thread ha il compito di comunicare con il sistema mobile per la ricezione degli id e 
    l'invio della conferma certificazione posizione.
'''
def server_sm_cli() :
    # crea connessione TCP con il sistema mobile (per ricezione id)
    TCPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPServerSocket.bind((host_sc_sm, port_sc_sm))
    TCPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # setta il socket in modalità ascolto
    TCPServerSocket.listen()
    
    # rimane in ascolto di nuove connessioni con il sistema mobile e se ne arriva una avvia un thread per gestirla
    while esegui:
        # stabilisci connessione TCP con il sistema mobile
        c, addr = TCPServerSocket.accept() #addr è una tupla che contiene [ip, porta]

        #gestisco SIGTERM
        if esegui == False:
            c.close()
            print("termina server_sm_cli")
            return
        
        thread_server_sm_cli = Thread(target=thread_sm_cli, args=(c, cursor, conn))
        print("Connessione TCP con sistema mobile (cli), host:"+str(addr[0])+", porta:"+str(addr[1]))
        thread_server_sm_cli.start()
         
    c.close()
            
'''
    Server TCP che comunica con il sistema mobile.
    Gli argomenti passati sono i seguenti:
    cursor: usato per Postgres
    conn: usato per Postgres
    counter: serve per associare ad ogni .zip e .json un id
'''
def server_sm (cursor, conn, counter, counter_lock) :
    cont_sm = 0 #associa un id a ogni sistema mobile che si collega
    
    # crea connessione TCP con il sistema mobile
    TCPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPServerSocket.bind((host_sm, port_sm))
    TCPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # setta il socket in modalità ascolto
    TCPServerSocket.listen()
    
    # rimane in ascolto di nuove connessioni con il sistema mobile e se ne arriva una avvia un thread per gestirla
    while esegui :
        cont_sm = cont_sm + 1
        # stabilisci connessione TCP con il sistema mobile
        c, addr = TCPServerSocket.accept() #addr è una tupla che contiene [ip, porta]
        thread_server_sm = Thread(target=thread_sm, args=(c, algod_client, cursor, conn, cont_sm,counter, counter_lock))
        
        #gestisco SIGTERM
        if esegui == False:
            c.close()
            print("chiudo server_sm")
            return
        
        print("Connesso con TCP sistema mobile " + str(cont_sm) + " con host:"+str(addr[0])+", porta:"+str(addr[1]))
        thread_server_sm.start()
         
    c.close()

'''
    Server TCP che comunica con la stazione di riferimento
    Gli argomenti passati sono i seguenti:
    counter: serve per associare ad ogni .zip e .json un id
'''
def server_sr (counter, counter_lock) :
    cont_sr = 0 #associa un id a ogni sistema mobile che si collega
    
    # crea connessione TCP con la stazione di riferimento
    TCPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPServerSocket.bind((host_sr, port_sr))

    # setta il socket in modalità ascolto
    TCPServerSocket.listen()

    # rimane in ascolto di nuove connessioni con il sistema mobile e se ne arriva una avvia un thread per gestirla
    while esegui :
        cont_sr = cont_sr + 1
        #stabilisci connessione TCP con la stazione di riferimento
        c, addr = TCPServerSocket.accept() #addr è una tupla che contiene [ip, porta]
        thread_server_sr = Thread(target = thread_sr, args=(c, cont_sr,counter, counter_lock))
        
        #gestisco SIGTERM
        if esegui == False:
            c.close()
            print("chiudo server_sr")
            return
        
        print("Connesso con TCP stazione di riferimento " + str(cont_sr) + " con host:"+str(addr[0])+", porta:"+str(addr[1]))
        thread_server_sr.start()

    c.close()


if __name__ == "__main__":
    
    #registro i segnali da catturare
    signal.signal(signal.SIGTERM, signal_TERM)  

    #estrai dati da info_algorand.json
    config_file = json.load(open("info_algorand.json"))
    sistema_centrale_address = config_file["sistema_centrale_address"]
    sistema_centrale_privatekey = config_file["sistema_centrale_privatekey"]
    sistema_centrale_passphrase = config_file["sistema_centrale_passphrase"]
    app_id = config_file["app_id"]
    
    #app id
    print("[app-id: "+ str(app_id) + " ]")
    
    #configurazione algodClient
    # tramite sandbox (alternativa 1)
    # user declared algod connection parameters. Node must have EnableDeveloperAPI set to true in its config
    if SANDBOX :
        algod_address = "http://localhost:4001"
        algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        algod_client = algod.AlgodClient(algod_token, algod_address) 
    else :
        # tramite purestake (alternativa 2)
        headers = {
        "X-API-Key": "L8NJ22dpve6TjszRmN16t6Zf5BMD0sypaZ8tWfW6",
        }
        algod_client = algod.AlgodClient("", "https://testnet-algorand.api.purestake.io/ps2", headers)
        
    #SEGNALE
    signal.signal(signal.SIGTERM, signal_TERM)
    
    #inizializzo i contatori
    counter = Counter() #sistema mobile
    counter2 = Counter() #stazione di riferimento
    counter_lock = Counter_lock() #stazione di riferimento
    
    # crea se non esiste o apri il file 'object_storage.json'
    try:
        f = open('/data/object_storage.json',) 
    except FileNotFoundError as err:
        with open('/data/object_storage.json', 'w') as outfile:
            data = {}
            json.dump(data, outfile)
    # crea se non esiste o apri il file 'metadati.json'
    try:
        f2 = open('/data/metadati.json',) 
    except FileNotFoundError as err:
        with open('/data/metadati.json', 'w') as outfile:
            data = {}
            json.dump(data, outfile)
        
    #configurazione database PostgreSQL
    db_start = True
    while db_start: #attendi finchè non si connette al database
        try :
            conn = psycopg2.connect(user="postgres", password="postgres", database="postgres", host="db", port="5432")
            db_start = False
        except Exception as err:
            if str(err).find("could not connect to server: Connection refused") != -1:
                #print("attendi connessione con postgres db ...")
                pass
            else :
                print(err)
            db_start = True
                 
    if (database_library.DEBUG == True): 
        print("*Database PostgreSQL connesso.")
    conn.autocommit = True
    cursor = conn.cursor()
    # database_library.delete_table(cursor, conn, 'SNAPSHOT_LIST')
    # database_library.delete_database(cursor, 'SNAPSHOT_LIST')
    database_library.create_database(cursor, 'SNAPSHOT_LIST')
    database_library.create_table_snapshot_list (cursor, conn)
    
    #server per comunicare con sistema mobile
    thread_server_sm = Thread(target=server_sm, args=(cursor,conn, counter, counter_lock,))
    thread_server_sm.start()
    #server per comunicare con la stazione di riferimento
    thread_server_sr = Thread(target=server_sr,args=(counter2,counter_lock,))
    thread_server_sr.start()
    #avvio server che attende l'id da parte di sistema mobile
    thread_server_sm_cli = Thread(target=server_sm_cli, args=())
    thread_server_sm_cli.start()
    
    thread_server_sm.join()
    print("thread_server_sm terminato")
    thread_server_sr.join()
    print("thread_server_sr terminato")
    thread_server_sm_cli.join()
    print("thread_server_sm_cli terminato")
    
    print("sistema centrale terminato correttamente!")
import time, json, base64, os

from algosdk.v2client import algod
from algosdk.future import transaction
from algosdk import account, mnemonic, logic
from pyteal import *
from algosdk.constants import min_txn_fee
from algosdk import account, mnemonic
from algosdk import mnemonic

#account intecs
intecs_address="7CHEQ5INS7VAHLDTMAACBNBAEUOPYW2YRPRO47J6QPNK5Z4F7EG7H4MYHI"
intecs_privatekey="MPv2d5S1jLB6ojvBR2eknZ3D3qKaHVPI6MtLuZh6KTj4jkh1DZfqA6xzYAAgtCAlHPxbWIvi7n0+g9qu54X5DQ=="
intecs_passphrase="gravity swim desk flock bonus promote because desert wealth other split supply mango response steak budget apology permit tourist net cousin gadget scout ability human"

#account sistema centrale
sistema_centrale_address="QVCK3TLA4WNNX22Y3HGNEX2FZTXT24WG6HMX3M2SELRYFBKU4MNQ7I435Y"
sistema_centrale_privatekey="wrN7d4ma6QF99xMqi0OAueYkSZHYvWYZABzG6q9QPgqFRK3NYOWa2+tY2czSX0XM7z1yxvHZfbNSIuOChVTjGw=="
sistema_centrale_passphrase="joke uphold roof possible spring document room become grab athlete scan high endorse false setup saddle coast about asthma property garlic neither faint abandon just"


def generate_algorand_keypair():
    private_key, address = account.generate_account()
    print("My address: {}".format(address))
    print("My private key: {}".format(private_key))
    print("My passphrase: {}".format(mnemonic.from_private_key(private_key)))

# helper function to compile program source
def compile_program(client, source_code):
    compile_response = client.compile(source_code)
    return base64.b64decode(compile_response['result'])

# helper function that formats global state for printing
def format_state(state):
    formatted = {}
    for item in state:
        key = item['key']
        value = item['value']
        formatted_key = base64.b64decode(key).decode('utf-8')
        if value['type'] == 1:
            # byte string
            if formatted_key == 'voted':
                formatted_value = base64.b64decode(value['bytes']).decode('utf-8')
            else:
                formatted_value = value['bytes']
            formatted[formatted_key] = formatted_value
        else:
            # integer
            formatted[formatted_key] = value['uint']
    return formatted

# helper function that converts a mnemonic passphrase into a private signing key
def get_private_key_from_mnemonic(mn) :
    private_key = mnemonic.to_private_key(mn)
    return private_key

# helper function to read app global state
def read_global_state(client, app_id):
    app = client.application_info(app_id)
    global_state = app['params']['global-state'] if "global-state" in app['params'] else []
    return format_state(global_state)

def approval_program():
    
    #globals
    global_address_sc = Bytes("address_sistema_centrale") #byteslice
    
    #locals
    local_hash_snapshot_sm = Bytes("hash_snapshot_sm") #byteslice
    
    #operations
    op_set_address_sistema_centrale = Bytes("set_address_sistema_centrale")
    op_insert_local_hash_snapshot_sm = Bytes("insert_local_hash_snapshot_sm")
    op_compare_hash = Bytes("compare_hash")
    op_validate_snapshot = Bytes("validate_snapshot")
    
    
    on_creation = Seq([
        App.globalPut(global_address_sc, Bytes("")), #byteslice
        Return(Int(1))
    ])

    handle_optin = Seq([
        If (Global.creator_address() == Txn.sender())
        .Then(
            App.globalPut(global_address_sc, Txn.accounts[1]) #setto variabile globale
        )
        .Else(
            App.localPut(Txn.sender(), local_hash_snapshot_sm, Bytes("")) #setto variabile globale
            
        ),
        Return(Int(1))
    ])

    handle_closeout = Return(Int(1))

    handle_updateapp = Seq([
        Assert(Txn.sender() == Global.creator_address()),
        Return(Int(1)),
    ])

    handle_deleteapp = Seq([
        Assert(Txn.sender() == Global.creator_address()),
        Return(Int(1)),
    ])

    set_address_sistema_centrale = Seq([
        If (Global.creator_address() == Txn.sender())
        .Then(
            App.globalPut(global_address_sc, Txn.application_args[1]) #setto variabile globale
        ),
        Return(Int(1))
    ])

    insert_local_hash_snapshot_sm = Seq([
        If (Global.creator_address() != Txn.sender())
        .Then(
            App.localPut(Txn.sender(), local_hash_snapshot_sm, Txn.application_args[1]) #setto variabile globale
        ),
        Return(Int(1))
    ])
    
    compare_hash = Seq([
        Assert(App.globalGet(global_address_sc) == Txn.sender()),
        Assert(App.localGet(Txn.accounts[1], local_hash_snapshot_sm) == Txn.application_args[1]),
        Return(Int(1)),
    ])
    
    validate_snapshot = Seq([
        Assert(App.globalGet(global_address_sc) == Txn.sender()),
        Return(Int(1)),
    ])
    
    
    handle_noop = Cond(
        [Gtxn[0].application_args[0] == op_set_address_sistema_centrale, set_address_sistema_centrale],
        [Gtxn[0].application_args[0] == op_insert_local_hash_snapshot_sm, insert_local_hash_snapshot_sm],
        [Gtxn[0].application_args[0] == op_compare_hash, compare_hash],
        [Gtxn[0].application_args[0] == op_validate_snapshot, validate_snapshot],
        
    )


    program = Cond(
        [Txn.application_id() == Int(0), on_creation],
        [Txn.on_completion() == OnComplete.OptIn, handle_optin],
        [Txn.on_completion() == OnComplete.CloseOut, handle_closeout],
        [Txn.on_completion() == OnComplete.UpdateApplication, handle_updateapp],
        [Txn.on_completion() == OnComplete.DeleteApplication, handle_deleteapp],
        [Txn.on_completion() == OnComplete.NoOp, handle_noop],
    )
    # Mode.Application specifies that this is a smart contract
    return compileTeal(program, Mode.Application, version=5)


def clear_state_program():
    program = Return(Int(1))
    # Mode.Application specifies that this is a smart contract
    return compileTeal(program, Mode.Application, version=5)

# create new application
def create_app(client, private_key, approval_program, clear_program, global_schema, local_schema):
    # define sender as creator
    sender = account.address_from_private_key(private_key)

    # declare on_complete as NoOp
    on_complete = transaction.OnComplete.NoOpOC.real

    # get node suggested parameters
    params = client.suggested_params()
    params.fee = min_txn_fee
    params.flat_fee = True
    
    # create unsigned transaction
    txn = transaction.ApplicationCreateTxn(sender, params, on_complete, \
                                            approval_program, clear_program, \
                                            global_schema, local_schema)

    # sign transaction
    signed_txn = txn.sign(private_key)
    tx_id = signed_txn.transaction.get_txid()

    # send transaction
    client.send_transactions([signed_txn])

    # wait for confirmation
    try:
        transaction_response = transaction.wait_for_confirmation(client, tx_id, 5)
        #print("TXID: ", tx_id)
        #print("Result confirmed in round: {}".format(transaction_response['confirmed-round']))

    except Exception as err:
        print(err)
        return

    # display results
    transaction_response = client.pending_transaction_info(tx_id)
    #print(transaction_response)
    app_id = transaction_response['application-index']
    print("Creata nuova app con id ",app_id)

    return app_id

# opt_in 
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
    except Exception as err:
        print("[optin exception] ",err)
        return

    # wait for confirmation
    try:
        transaction_response = transaction.wait_for_confirmation(client, tx_id, 5)
        #print("TXID: ", tx_id)
        #print("Result confirmed in round: {}".format(transaction_response['confirmed-round']))
    except Exception as err:
        print("[optin exception] ",err)
        return

    return

# delete application
def delete_app(client, private_key, index, app_args, accounts) :
    # declare sender
    sender = account.address_from_private_key(private_key)

    # get node suggested parameters
    params = client.suggested_params()
    params.fee = min_txn_fee
    params.flat_fee = True
     
    # create unsigned transaction
    txn = transaction.ApplicationDeleteTxn(sender, params, index, app_args, accounts)
    # sign transaction
    signed_txn = txn.sign(private_key)
    tx_id = signed_txn.transaction.get_txid()

    # send transaction
    client.send_transactions([signed_txn])

    # wait for confirmation
    try:
        transaction_response = transaction.wait_for_confirmation(client, tx_id, 4)
        #print("TXID: ", tx_id)
        #print("Result confirmed in round: {}".format(transaction_response['confirmed-round']))

    except Exception as err:
        print(err)
        return
    print("Applicazione eliminata")

# call application
def call_app(client, private_key, index, app_args, accounts) :
    # declare sender
    sender = account.address_from_private_key(private_key)

    # get node suggested parameters
    params = client.suggested_params()
    params.fee = min_txn_fee
    params.flat_fee = True
     
    # create unsigned transaction
    txn = transaction.ApplicationNoOpTxn(sender, params, index, app_args, accounts)
    # sign transaction
    signed_txn = txn.sign(private_key)
    tx_id = signed_txn.transaction.get_txid()

    # send transaction
    client.send_transactions([signed_txn])

    # wait for confirmation
    try:
        transaction_response = transaction.wait_for_confirmation(client, tx_id, 4)
        #print("TXID: ", tx_id)
        #print("Result confirmed in round: {}".format(transaction_response['confirmed-round']))

    except Exception as err:
        print(err)
        return
    
def help() :
    #suggerimenti
    print("create_app: crea una nuova applicazione ")
    time.sleep(0.05)
    print("app-id: restituisce l'app-id")
    time.sleep(0.05)
    print("delete_app: elimina l'app")
    time.sleep(0.05)
    print("set_account_sistemacentrale <account>: cambia l'indirizzo Algorand di sistema centrale")
    time.sleep(0.05)
    print("exit: esci dal Terminale")
    time.sleep(0.05)
    print("clear: pulisci lo schermo")
    time.sleep(0.05)

#controllo esistenza app, se non esiste chiede di crearla e fa anche
#l'operazione di opt-in
'''
    Controlla l'esistenza dell'applicazione controllando il valore di 'app_id' nel file 'config.json'.
    Se il valore è 0 si richiede di creare l'applicazione. Dopo aver creato l'app viene anche fatta
    l'operazione di opt-in.
'''
def check_and_create_app(primo_avvio, app_id):
    #controlla esistenza applicazione
    config_json = json.load(open("config.json"))
    if (config_json["app_id"] == 0):
        print("applicazione inesistente, si desidera crearla? [SI/NO]")
        msg = input()
        if (msg == "SI"):
            try:
                app_id = create_app(algod_client, intecs_privatekey, approval_program_compiled, clear_state_program_compiled, global_schema, local_schema)
                print("Attenzione: ricorda di cambiare manualmente l'app-id di sistema mobile e di sistema centrale")
                app_account = logic.get_application_address(app_id)
                #salva app_id in config.json
                config_json = {"app_id" : app_id} 
                with open("config.json", "w") as outfile:
                    json.dump(config_json, outfile)
                #opt_in
                accounts = [sistema_centrale_address]
                opt_in(algod_client, intecs_privatekey, app_id, None, accounts)
                primo_avvio=False      
            except Exception as err:
                print(err)
        elif (msg == "NO"):
            print("applicazione non creata")
        else: 
            print('comando non riconosciuto, digita "help" per i suggerimenti')
            primo_avvio=False 
            
    return primo_avvio
                 
if __name__ == "__main__":
    
    primo_avvio = True #usata per capire se stampare help() oppure no al primo avvio
    
    #configurazione algodClient
    headers = {
    "X-API-Key": "L8NJ22dpve6TjszRmN16t6Zf5BMD0sypaZ8tWfW6",
    }
    '''
    # tramite sandbox (alternativa 1)
    # user declared algod connection parameters. Node must have EnableDeveloperAPI set to true in its config
    algod_address = "http://localhost:4001"
    algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    algod_client = algod.AlgodClient(algod_token, algod_address) 
    '''
    # tramite purestake (alternativa 2)
    algod_client = algod.AlgodClient("", "https://testnet-algorand.api.purestake.io/ps2", headers)

    # declare application state storage (immutable)
    local_ints = 0
    local_bytes = 1
    global_ints = 0
    global_bytes = 1
    global_schema = transaction.StateSchema(global_ints, global_bytes)
    local_schema = transaction.StateSchema(local_ints, local_bytes)

    # compile program to TEAL assembly
    with open("approval.teal", "w") as f:
        approval_program_teal = approval_program()
        f.write(approval_program_teal)   
    with open("clear.teal", "w") as f:
        clear_state_program_teal = clear_state_program()
        f.write(clear_state_program_teal)
    
    # compile program to binary
    approval_program_compiled = compile_program(algod_client, approval_program_teal)
    clear_state_program_compiled = compile_program(algod_client, clear_state_program_teal)
    
    
    print("Terminale Intecs")
    time.sleep(0.05)
    
    #controllo correttezza config.json
    config_json = json.load(open("config.json"))
    try :
        app_id = int(config_json["app_id"])
    except Exception as err :
        print("il file config.json è corrotto, si desidera ricrearlo? [SI/NO] Attenzione: questa operazione cancellerà il contenuto!")
        if (input() == "SI") :
            config_json = {"app_id" : 0} 
            with open("config.json", "w") as outfile:
                json.dump(config_json, outfile)
        
    #esegui controlli vari
    primo_avvio = check_and_create_app(primo_avvio, app_id)                 
    
    if (primo_avvio == True): 
        print('digita "help" per info sui comandi')
    
    while True:
        print(">>", end="")
        msg = input()
        #comando help
        if (msg == "help"):
            help()
        #comando set_account_sistemacentrale
        elif (msg.startswith("set_account_sistemacentrale")):
            str = msg.split()
            if (len(str) != 2): 
                print('comando non riconosciuto, digita "help" per i suggerimenti')               
            else:
                app_args = ["set_address_sistema_centrale".encode()]
                accounts = [str[1]]
                call_app(algod_client, intecs_privatekey, app_id, app_args, accounts)
                print("account settato correttamente")
                
        #comando per restituire app-id
        elif (msg == "app-id"):
            if (app_id == 0):
                print("app inesistente, impossibile restituire l'app-id")
            else:
                print(app_id)
        #comando create_app
        elif (msg == "create_app"):
            #controlla esistenza applicazione
            config_json = json.load(open("config.json"))
            if (config_json["app_id"] == 0) :
                print("applicazione inesistente, si desidera crearla? [SI/NO]")
                msg = input()
                if (msg == "SI"):
                    app_id = create_app(algod_client, intecs_privatekey, approval_program_compiled, clear_state_program_compiled, global_schema, local_schema)
                    print("Attenzione: ricorda di cambiare manualmente l'app-id del file info_algorand.json di sistema mobile e di sistema centrale")
                    #salva app_id in config.json
                    config_json = {"app_id" : app_id} 
                    with open("config.json", "w") as outfile:
                        json.dump(config_json, outfile)
                    #opt_in
                    accounts = [sistema_centrale_address]
                    opt_in(algod_client, intecs_privatekey, app_id, None, accounts)
                elif (msg == "NO"):
                    print("applicazione non creata")
                else: 
                    print('comando non riconosciuto, digita "help" per i suggerimenti')
                    
            else:
                print("applicazione esistente con id " + str(app_id) + ", per crearne una nuova è necessario eliminare prima quella che già esiste")
        #comando delete_app
        elif(msg == "delete_app"):
            if (app_id != 0):
                print("sei sicuro di voler eliminare l'app con id " + str(app_id) + "? [SI/NO]")
                msg = input()
                if (msg == "SI"):   
                    print("eliminazione in corso......")
                    delete_app(algod_client, intecs_privatekey, app_id, None, None)
                    #reset app_id in config.json
                    config_json = {"app_id" : 0} 
                    with open("config.json", "w") as outfile:
                        json.dump(config_json, outfile)
                    #reset app_id   
                    app_id = 0
                elif (msg == "NO"): 
                    print("applicazione non eliminata") 
                else:        
                    print('comando non riconosciuto, digita "help" per i suggerimenti')               
            else:
                print("app inesistente, impossibile eliminarla")
        #comando exit
        elif(msg == "exit"):
            quit()
        #comando clear
        elif(msg == "clear"):
            os.system('cls' if os.name == 'nt' else 'clear')
        #comando non riconosciuto
        else :
            print('comando non riconosciuto, digita "help" per i suggerimenti')
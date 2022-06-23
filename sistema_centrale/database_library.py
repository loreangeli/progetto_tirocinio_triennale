import psycopg2
from threading import Thread, Lock

DEBUG = True

def create_database (cursor, database_name) :
    #Preparing query to create a database
    sql = '''CREATE database ''' + database_name

    #Creating a database
    try :
        cursor.execute(sql)
        print("Database creato con successo...")
    except psycopg2.DatabaseError as e:
        if (DEBUG == True): print("Database già esistente! Impossibile crearlo.")
        pass

def delete_database (cursor, database_name) :
    sql = '''DROP DATABASE ''' + database_name

    try :
        cursor.execute(sql)
        print("Database eliminato con successo..")
    except psycopg2.DatabaseError as e:
        if (DEBUG == True): print("Database inesistente, impossibile eliminarlo..")
        pass
    
def create_table_snapshot_list (cursor, conn) :
    #Creating table as per requirement
    sql ='''CREATE TABLE SNAPSHOT_LIST(ID CHAR(64) PRIMARY KEY, RISULTATO BOOLEAN NOT NULL)'''
    try :
        cursor.execute(sql)
        print("Tabella creata con successo..")
    except psycopg2.DatabaseError as e:
        if (DEBUG==True): print ("Tabella già esistente! Impossibile crearla.")
        pass

    conn.commit()
   
def delete_table (cursor, conn, table_name) :
    sql =''' DROP TABLE ''' + table_name
    try :
        cursor.execute(sql)
        print("Tabella eliminata: ",table_name)
    except psycopg2.DatabaseError :
        print("Tabella inesistente! Impossibile eliminarla.")
    conn.commit()
 
 #aggiunge record <id_snapshot, true/false> al database 'SNAPSHOT_LIST'
 #id_snapshot lo si calcola facendo l'hash del file .zip ricevuto da sistema mobile
 #check: può valere True o False
def add_snapshot(cursor, conn, id, check, lock_database) :
    lock_database.acquire()
    risultato = str(check)
    sql = '''INSERT INTO SNAPSHOT_LIST(ID, RISULTATO) VALUES (''' + "'" +str(id) + "'" +  ''', ''' + "'" +risultato + "'" + ''')'''
    #print('inserito record: <' + id + ',' + risultato + '> nel database')
    cursor.execute(sql)
    conn.commit()
    lock_database.release()
       
def delete_snapshot(cursor, conn, id, lock_database) :
    lock_database.acquire()
    sql = '''DELETE FROM SNAPSHOT_LIST WHERE ID=''' + "'"+ str(id) + "'"
    try:
        cursor.execute(sql)
        #print('rimuovi record con id ' + str(id) + '' + ' dal database')
    except Exception as e :
        print("record con id "+str(id)+ " non presente")
        lock_database.release()
        
    conn.commit()
    lock_database.release()
    
def print_table(conn) :
    try :
        cur = conn.cursor()
        #cur.execute("SELECT * from SNAPSHOT_LIST")
        cur.execute("TABLE SNAPSHOT_LIST")
        
        rows = cur.fetchall()
        for row in rows:
            print("ID: ", row[0])
            print("RISULTATO: ",row[1])
    except Exception as err  :
        print("impossibile stampare, nessuna tabella esistente")
        
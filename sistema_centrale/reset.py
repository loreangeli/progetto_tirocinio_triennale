'''
Strumento da avviare se si vuole eliminare la tabella e il database 'SNAPSHOT_LIST'.
Per eliminare il database del sistema centrale dove vengono salvati i due file 'metadati.json' e 'object_storage.json'
e i vari pacchetti .zip e .json ricevuti dai sistemi mobili e dalle stazioni di riferimento cancellare direttamente i Volumi da Docker
Desktop.
'''
import psycopg2
import database_library

#configurazione database PostgreSQL
db_start = True
while db_start: #attendi finchè non si connette al database
    try :
        conn = psycopg2.connect(user="postgres", password="postgres", database="postgres", host="localhost", port="5432")
        db_start = False
    except Exception as err:
        print(err)
        db_start = True
        
conn.autocommit = True
cursor = conn.cursor()
database_library.delete_table(cursor, conn, 'SNAPSHOT_LIST')
database_library.delete_database(cursor, 'SNAPSHOT_LIST')
### Prerequisiti
Assicurati di aver installato Docker Desktop  

### Installazione e configurazione della sandbox
Installa queste due cartelle nell'area di lavoro  
```bash
git clone https://github.com/algorand/sandbox.git  
git clone https://github.com/algorand-devrel/pyteal-course.git  

cd project
python -m venv venv
source ./venv/Scripts/activate
pip install -r ./requirements.txt
```

Apri il docker-compose.yml e aggiungi questa parte di volumes:
```bash
    ports:  
        - 4001:4001  
        - 4002:4002  
        - 9392:9392  
    volumes:  
        - type: bind  
                source: ../project  
                target: /data
```

Avvia successivamente la rete testnet  
```bash
cd ..  
cd sandbox  
./sandbox up testnet  
```
####

### Avvio e spegnimento del progetto
Per avviare il progetto, utilizzare il seguente comando: 
```bash
docker-compose up --build
```
Per terminare correttamente il progetto, utilizzare il seguente comando: 
```bash
docker down
```

### LINK UTILI
INSTALLAZIONE DELLA SANDBOX DA ZERO: https://www.youtube.com/watch?v=V3d3VTlgMo8&list=PLpAdAjL5F75CNnmGbz9Dm_k-z5I6Sv9_x&ab_channel=Algorand  

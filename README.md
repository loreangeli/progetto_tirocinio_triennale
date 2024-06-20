hints: ricorda di avviare la sandbox e successivamente il progetto; assicurati di aver installato Docker Desktop.
 
INSTALLAZIONE DELLA SANDBOX DA ZERO -> https://www.youtube.com/watch?v=V3d3VTlgMo8&list=PLpAdAjL5F75CNnmGbz9Dm_k-z5I6Sv9_x&ab_channel=Algorand
#installa queste due cartelle nell'area di lavoro
git clone https://github.com/algorand/sandbox.git
git clone https://github.com/algorand-devrel/pyteal-course.git

cd project
python -m venv venv
source ./venv/Scripts/activate
pip install -r ./requirements.txt

#apri il docker-compose.yml e aggiungi questa parte di volumes:
    ports:
        - 4001:4001
        - 4002:4002
        - 9392:9392
    volumes:
        - type: bind
                source: ../project
                target: /data
####

cd ..
cd sandbox
./sandbox up testnet

####

Per avviare il progetto, utilizzare il seguente comando: docker-compose up --build
Per far terminare il progetto correttamente utilizzare il seguente comando: docker down

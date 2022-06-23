# Same thing than the 'server' Dockerfile.
FROM python:latest

RUN pip3 install py-algorand-sdk

# Same thing than the 'server' Dockerfile.
# We import 'client.py' in '/client/' folder.
ADD stazioneriferimento.py /stazione_di_riferimento/
ADD utility.py /stazione_di_riferimento/

# I would like to introduce something new, the 'WORKDIR' command.
# This command changes the base directory of your image.
# Here we define '/client/' as base directory.
WORKDIR /stazione_di_riferimento/

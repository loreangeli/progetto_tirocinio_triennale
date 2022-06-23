# Same thing than the 'server' Dockerfile.
FROM python:latest

RUN pip3 install py-algorand-sdk

# Same thing than the 'server' Dockerfile.
# We import 'client.py' in '/client/' folder.
ADD sistemamobile.py /sistema_mobile/
ADD info_algorand.json /sistema_mobile/
ADD utility.py /sistema_mobile/


# I would like to introduce something new, the 'WORKDIR' command.
# This command changes the base directory of your image.
# Here we define '/client/' as base directory.
WORKDIR /sistema_mobile/

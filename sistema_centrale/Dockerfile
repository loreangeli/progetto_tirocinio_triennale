# Just a remember, dockerfile must always start by importing the base image.
# We use the keyword 'FROM' to do that.
# In our example, we want to import the python image (from DockerHub).
# So, we write 'python' for the image name and 'latest' for the version.
FROM python:latest

RUN pip3 install py-algorand-sdk
RUN pip install psycopg2

# In order to launch our python code, we must import the 'server.py' and 'index.html' file.
# We use the keyword 'ADD' to do that.
# Just a remember, the first parameter 'server.py' is the name of the file on the host.
# The second parameter '/server/' is the path where to put the file on the image.
# Here we put files at the image '/server/' folder.
ADD sistemacentrale.py /sistema_centrale/
ADD info_algorand.json /sistema_centrale/
ADD database_library.py /sistema_centrale/
ADD utility.py /sistema_centrale/


# I would like to introduce something new, the 'WORKDIR' command.
# This command changes the base directory of your image.
# Here we define '/server/' as base directory (where all commands will be executed).
WORKDIR /sistema_centrale/

EXPOSE 4001
EXPOSE 4002
EXPOSE 9392
EXPOSE 5433
EXPOSE 8980
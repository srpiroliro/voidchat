from pprint import pprint
import socket
from queue import Queue

HOST = "127.0.0.1"
PORT = 1111

INFO_SEP="|"

chats={}

def handle_client(connection):
    while True:
        data=connection.recv(2024)
        if not data: continue
        
        recieved_command=data.decode()
        if recieved_command.count(INFO_SEP) != 2: continue
        source, destionation, message = recieved_command.split(INFO_SEP)
        
        if destionation not in chats: chats[destionation]={}
        if source not in chats[destionation]: chats[destionation][source]=[]#Queue()
        # chats[destionation][source].put(message)
        chats[destionation][source].append(message)

        pprint(chats)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind((HOST, PORT))
    sock.listen()
    connection, address = sock.accept()

    with connection:
        connection.sendall("[ ---  welcome.  --- ]".encode())

        handle_client(connection)

        connection.sendall("[ ---  goodbye.  --- ]".encode())
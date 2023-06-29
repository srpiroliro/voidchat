import socket

HOST = "127.0.0.1"
PORT = 1111

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    data=s.recv(2024)
    print(f"{data.decode()}")
    
    while True:
        message=input(" > ")
        s.sendall(message.encode())

        # data=s.recv(2024)
        # if data: print(f" - {data.decode()}")

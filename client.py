from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding


import socket, time, getpass
from os.path import exists
from os import mkdir




class Client:
    HOST:str="127.0.0.1"
    PORT:int=1111
    ENCODING:str="utf-8"
    MESSAGE_SIZE:int=2048
    MESSAGE_SEPARATOR:str="|"


    KEY_SIZE:int=2048
    KEYS_FOLDER:str="keys"
    PUB_KEY_PATH:str=f"{KEYS_FOLDER}/public_key.pem"
    PRIV_KEY_PATH:str=f"{KEYS_FOLDER}/private_key.pem"

    def __init__(self, socket:socket.socket=None)->None:
        self.socket=socket
    
    def gen_keys(self)->tuple[str]:
        if not exists(self.KEYS_FOLDER): 
            mkdir(self.KEYS_FOLDER)

        private_key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.KEY_SIZE
        )

        encrypted_pem_private_key=self.__gen_private_key(private_key)
        pem_public_key=self.__gen_public_key(private_key)


        self.__save_keys(encrypted_pem_private_key, pem_public_key)
        
    def __gen_private_key(self, private_key:RSAPrivateKey):
        private_key_pass=self.__ask_password()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
        )

    def __gen_public_key(self, private_key:RSAPrivateKey):
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def __save_keys(self,private_key,public_key)->None:
        private_key_file=open(self.PRIV_KEY_PATH, "w")
        private_key_file.write(private_key.decode())
        private_key_file.close()

        public_key_file=open(self.PUB_KEY_PATH, "w")
        public_key_file.write(public_key.decode())
        public_key_file.close()

    def load_keys(self)->tuple[str]:
        if not (exists(self.PRIV_KEY_PATH) and exists(self.PRIV_KEY_PATH)):
            self.set_keys()

        with open(self.PUB_KEY_PATH, "rb") as key_file:
            public_key=serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        with open(self.PRIV_KEY_PATH, "rb") as key_file:
            private_key=serialization.load_pem_private_key(
                key_file.read(),
                password=self.__ask_password(),
                backend=default_backend()
            )

        self.private_key=private_key
        self.public_key=public_key
        
    def __ask_password(self, prompt:str="password: ",  confirm_prompt:str="confirm password: ", new_password:bool=False)->str:
        try: 
            password=getpass.getpass(prompt=prompt)
            if new_password: confirmation=getpass.getpass(prompt=confirm_prompt)
        except Exception as e:
            print("ERROR:",e)
            return self.__ask_password()
        else:
            if password==confirmation or not new_password: 
                return password
            
            print("passwords don't match!")
            return self.__ask_password()
    
    def connect(self)->None:
        self.socket.connect((self.HOST, self.PORT))

    def listen(self)->str|None:
        received:bytes=self.socket.recv(self.MESSAGE_SIZE)
        if received: return received.decode(self.ENCODING)
        return None

    def send(self, receiver_key:str, text:str)->None:
        sender_key:str=self.public_key
        timestamp:float=time.time() # seconds since Epoch

        data:list[str]=[timestamp, text]
        encrypted_data:str=self.encrypt(receiver_key, self.__join_by_sep(data))

        components:list[str]=[sender_key,receiver_key,encrypted_data]
        encrypted_message:str=self.__join_by_sep(components)

        self.socket.sendall(encrypted_message)

    def __join_by_sep(self, elem:list)->str:
        return self.MESSAGE_SEPARATOR.join(elem)

    def encrypt(self, receivers_pub_key, content:str)->str:
        # CHECK: receivers key needs to be "serialized"?

        return self.__encrypt_with_key(
            self.private_key,
            self.__encrypt_with_key(receivers_pub_key, content)
        )

    def __encrypt_with_key(self, key, content:str):
        return key.encrypt(
            content,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        )
        

    def start(self)->None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            self.socket=s
            self.connect()

            while True:
                message=input(" > ")
                s.sendall(message.encode())


    
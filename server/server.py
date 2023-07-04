from pprint import pprint

from queue import Queue
import socket, threading, json, rsa

HOST:str="127.0.0.1"
PORT:int=1111

HASH_METHOD="SHA-512"
PUB_KEY_MAX_LENGTH:int=128
VERIFICATION_KEY:str="vChat"

MESSAGE_SIZE:int=2048
ENCODING:str="utf-8"


PEM_PREFIX:str="-----BEGIN RSA PUBLIC KEY-----\n"
PEM_SUFFIX:str="\n-----END RSA PUBLIC KEY-----"

unsent_chats:dict={} # saves unsent messages in a format to be resent straight up.
clients:dict={}
clients["tmp"]=[]


class ClientThread(threading.Thread):
	def __init__(self, connection:socket.socket, address:str)->None:
		threading.Thread.__init__(self)

		self.conn=connection
		self.addr=address

		self.pub_key=None
		self.connected=True

	def resend(self, data:bytes):
		self.conn.sendall(data)

	def send(self, data:str):
		self.conn.sendall(data.encode(ENCODING))

	def run(self)->None:
		print("[NEW CONNECTION]:", self.addr)

		self.connected=self.__login()

		if self.connected:
			self.move()
			self.__send_unsent_messages()

		while self.connected:
			raw_data=self.conn.recv(MESSAGE_SIZE)
			if not raw_data: 
				print("no data here")
				break
			data=raw_data.decode()
			print("[received]:",data)

			try:  source, destionation, _ =self.__parse_message(data)
			except Exception as e:  print(f"[ERROR ({self.addr})]: wrong message format ('{e}')")
			else:
				if destionation in clients: 
					print(f"[RESENT TO '{destionation}' FROM '{source}']")
					clients[destionation].resend(data)
				else:
					print("[ADDED TO QUEUE]")
					if destionation not in unsent_chats:  unsent_chats[destionation]=Queue()
					unsent_chats[destionation].put(data)

		self.conn.close()
		print("[DISCONNECTED]")


	def __parse_message(self, message:str)->tuple:
		json_message=json.loads(message)

		return json_message["s"], json_message["de"], json_message["da"]

	def __login(self)->bool:
		try:
			raw_data=self.conn.recv(MESSAGE_SIZE)
			if not raw_data: self.connected=False
			data=raw_data.decode(ENCODING)

			source, destination, raw_message=self.__parse_message(data)
			message=json.loads(raw_message)

			if not destination==None: raise Exception("incorrect destination")
			if not self.__verify_message(source, message): raise Exception("opsie")

		except Exception as e: 
			print(f"[ERROR ({self.addr})]: {e}")
			return False
		else:
			self.pub_key=source
			self.conn.sendall("ok".encode())
			return True

		
	def __verify_message(self, raw_pub_key:str, data:dict)->bool:
		pub_key=rsa.PublicKey.load_pkcs1(bytes.fromhex(raw_pub_key), "DER")
		try:
			return rsa.verify(VERIFICATION_KEY.encode(), bytes.fromhex(data["txt"]), pub_key) == HASH_METHOD
		except Exception as e:
			print("Verification failed")

		return False

	def move(self)->None:
		# CHECK: inefficient?

		clients[self.pub_key]=self
		clients["tmp"].remove(self)

	def __send_unsent_messages(self)->None:
		if not self.pub_key in unsent_chats: return
		elif unsent_chats[self.pub_key].empty(): return
		
		messages_queue=unsent_chats[self.pub_key]
		while not messages_queue.empty():
			self.resend(messages_queue.get())


print("[ ---  WELCOME  --- ]")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
	sock.bind((HOST, PORT))
	sock.listen()

	while True:
		connection, address = sock.accept()

		thread=ClientThread(connection, address)
		thread.start()
		clients["tmp"].append(thread)

		print(f"[ACTIVE CONNECTIONS]: {threading.active_count() - 1}")
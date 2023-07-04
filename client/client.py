import base64, inquirer, rsa, socket, time, json, platform
from pprint import pprint

from queue import Queue
from os.path import exists
from os import mkdir, system
from threading import Thread
from datetime import datetime


"""
	Message structure:
		{
			"s": SENDER_PUB_KEY_HEX,
			"de": DESTINATION_PUB_KEY_HEX,
			"da": encrypted(
				with=DESTINATION_PUB_KEY,
				data={
					"t": SECONDS_TIMESTAMP,
					"txt": DATA,
					"sg": SIGNATURE( of what? )
				}
			)
		}
"""

class Client:
	COMMAND_KEY="!"
	CLEAR_COMMAND= "cls" if platform.system()=="Windows" else "clear"

	HOST:str="127.0.0.1"
	PORT:int=1111
	ENCODING:str="utf-8"
	MESSAGE_SIZE:int=2048

	VERIFICATION_KEY:str="vChat"
	SERVER_KEY:str|None=None

	KEY_SIZE:int=256
	KEYS_FOLDER:str="keys"
	PUB_KEY_PATH:str=f"{KEYS_FOLDER}/public_key.pem"
	PRIV_KEY_PATH:str=f"{KEYS_FOLDER}/private_key.pem"

	HASH_METHOD:str="SHA-512"

	MESSAGES_TO_LOAD=20

	def __init__(self, sock:socket.socket|None=None)->None:
		self.connected:bool=False

		self.chats:dict[str, list]={} # all message history (including own msgs)
		self.unread_chats:dict[str, Queue]={}

		self.chat_alias:dict={}
		self.current_chat:str|None=None
		
		self.connected:bool=False
		self.socket=sock if sock else socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		self.__ini_commands()

		self.start()

	def __ini_commands(self):
		self.commands:dict={
			"delete": self.delete_chat,
			"switch": self.pick_chat,
			"rename": self.rename
		}

	def connect(self)->None:
		self.socket.connect((self.HOST, self.PORT))
		self.connected=True

	def listen(self)->str|None:
		received:bytes=self.socket.recv(self.MESSAGE_SIZE)
		if received: return received.decode(self.ENCODING)

		self.connected=False
		return None
	
	def receive(self)->tuple|None:
		"""
			returns: sender, text, timetsamp
		"""

		raw_message_data:str|None=self.listen()
		if not raw_message_data: return

		message_data:dict=json.loads(raw_message_data)

		sender_key=rsa.PublicKey.load_pkcs1(bytes.fromhex(message_data["s"]),"DER")
		data:dict=json.loads(
			self.decrypt(message_data["da"]))
		
		self.verify(data["txt"], bytes.fromhex(data["sg"]), sender_key)
		
		return message_data["s"], data["txt"], data["t"]

	def send(self, receiver_key:str|None, text:str)->None:
		sender_key:str=self.public_key.save_pkcs1("DER").hex()
		timestamp:float=time.time()

		data:dict={"t":timestamp, "txt":text, "sg": self.sign(text)}
		encrypted_data:str=self.encrypt(receiver_key, json.dumps(data))

		components:dict={"s":sender_key, "de":receiver_key, "da":encrypted_data}
		encrypted_message:str=json.dumps(components)

		self.socket.sendall(encrypted_message.encode(self.ENCODING))

	
	def gen_keys(self)->None:
		if not exists(self.KEYS_FOLDER): 
			mkdir(self.KEYS_FOLDER)

		pub, priv = rsa.newkeys(self.KEY_SIZE)

		with open(self.PUB_KEY_PATH, 'wb') as f: f.write(pub.save_pkcs1('PEM'))
		with open(self.PRIV_KEY_PATH, 'wb') as f: f.write(priv.save_pkcs1('PEM'))

	def load_keys(self)->bool:
		try:
			with open(self.PUB_KEY_PATH, 'rb') as p:
				self.public_key=rsa.PublicKey.load_pkcs1(p.read())

			with open(self.PRIV_KEY_PATH, 'rb') as p:
				self.private_key=rsa.PrivateKey.load_pkcs1(p.read())
			
			return True
		except: return False
			
	def sign(self, message:str)->str:
		hashed_message=rsa.compute_hash(message.encode(), self.HASH_METHOD)
		return rsa.sign_hash(hashed_message, self.private_key, self.HASH_METHOD).hex()

	def verify(self, message, signature, pub_key)->bool:
		try:
			return rsa.verify(message, signature, pub_key)==self.HASH_METHOD
		except Exception: return False

	def encrypt(self, receivers_pub_key:str|None, content:str)->str:
		return self.__encrypt_with_key(receivers_pub_key, content)

	def __encrypt_with_key(self, key:str|None, content:str)->str:
		if not key: return content

		receiver_key=rsa.PublicKey._load_pkcs1_der(bytes.fromhex(key))
		cipher:bytes=rsa.encrypt(content.encode(self.ENCODING), receiver_key)

		return base64.b64encode(cipher).decode()

	def decrypt(self, content:str)->str:
		return rsa.decrypt(
				base64.b64decode(content.encode(self.ENCODING)), 
				self.private_key).decode()

	def login(self)->None:
		self.send(self.SERVER_KEY, self.sign(self.VERIFICATION_KEY))
		if not self.listen()=="ok":  raise Exception("ERROR LOGGING IN")

	
	def pick_chat(self)->None: 
		self.current_chat=None

		system(self.CLEAR_COMMAND)

		print("Personal address:\n\t", self.public_key.save_pkcs1("DER").hex())

		menu_options:list=self.__gen_chat_names()
		menu_options.append("Add new chat")

		question=inquirer.List("chat",message="Choose your chat:",choices=menu_options)
		answer=inquirer.prompt([question])

		if answer==None: return
		selected_answer:str=answer["chat"].strip().rsplit(" ")[0]

		if selected_answer=="Add":
			self.__create_new_chat()
			self.pick_chat()
		elif selected_answer.startswith("0x"):
			self.current_chat=self.__get_matching_chat(selected_answer)
		elif selected_answer in self.chat_alias:
			self.current_chat=self.chat_alias[selected_answer]

		system(self.CLEAR_COMMAND)

	# TODO: fix
	def __create_new_chat(self)->None:
		new_chat_key=input("Enter here the reciepients public key: ")
		if new_chat_key in self.chats: 
			print("Already exists!")
			return

		self.chats[new_chat_key]=[]

	def __gen_chat_names(self)->list[str]:
		all_chats:list[str]=list(self.chats.keys())
		names:list[str]=[]

		for chat in all_chats:
			name=self.__gen_chat_name(chat)
			if chat in self.unread_chats:
				name+="" if self.unread_chats[chat].empty() else f" [{self.unread_chats[chat].qsize()}]"
			names.append(name)
		return names

	def __gen_chat_name(self, chat:str)->str:
		if chat in self.chat_alias: return self.chat_alias[chat]
		return "0x"+chat[:8]+"..."

	def __get_matching_chat(self, piece:str)->str|None:
		chat_id:str=piece.strip("0x").strip("...")

		for chat in self.chats:
			if chat.startswith(chat_id): return chat
		
		return None

	def __print_message(self, timestamp, source, message)->None:
		print(f"{datetime.fromtimestamp(timestamp)} - [{self.__gen_chat_name(source)}]:",message,"\n")

	def __save_unread_message(self, timestamp, source, message)->None:
		if source not in self.unread_chats:  self.unread_chats[source]=Queue()
		self.unread_chats[source].put([timestamp, source, message])

	def __load_messages(self)->None:
		if not self.current_chat: return

		messages=self.chats[self.current_chat]
		messages_to_load=self.MESSAGES_TO_LOAD if self.MESSAGES_TO_LOAD<len(messages) else len(messages)

		for timestamp, source, message in messages[len(messages)-messages_to_load: ]:
			self.__print_message(timestamp, source, message)
		
		if self.current_chat in self.unread_chats:
			while not self.unread_chats[self.current_chat].empty():

				timestamp, source, message=self.unread_chats[self.current_chat].get()
				self.__print_message(timestamp, source, message)

	def __manage_command(self, command:str)->None:
		if command.strip("!") not in self.commands: return

		self.commands[command.strip("!")]()

	def delete_chat(self)->None:
		if not self.current_chat: 
			self.chats={}
			self.unread_chats={}
		else: self.chats[self.current_chat]=[]

		self.pick_chat()

	def rename(self)->None:
		if not self.current_chat: 
			print("Must be inside a chat.")
			return
		new_name:str=input("[NEW NAME FOR CURRENT CHAT]: ")
		if new_name in self.chat_alias: 
			print("Name already exists!")
			return
	
		self.chat_alias[new_name]=self.current_chat


	def start(self)->None:
		if not self.load_keys():  self.gen_keys()

		self.connect()
		self.login()
		
		listener:Thread=Thread(target=self.listener)
		speaker:Thread=Thread(target=self.speaker)

		listener.start()
		speaker.start()

	def listener(self)->None:
		while self.connected:
			data:tuple|None=self.receive()
			if not data: break

			source, message, timestamp =data
			if self.current_chat==source: 
				self.__print_message(timestamp, source, message)
				self.chats[source].append((timestamp, source, message))

			else: self.__save_unread_message(timestamp, source, message)
			
	
	def speaker(self)->None:
		self.pick_chat()

		while self.connected:
			pprint(self.chats)
			pprint(self.unread_chats)

			message:str=input("> ")

			if message.startswith(self.COMMAND_KEY) or not self.current_chat:
				self.__manage_command(message)
			else:
				self.send(self.current_chat, message)
				self.chats[self.current_chat].append((time.time(), "YOU", message))



if __name__=="__main__":
	c=Client()
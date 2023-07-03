import base64
import rsa, socket, time, json
from os.path import exists
from os import mkdir
from threading import Thread


"""
	Message structure:
		{
			"s": SENDER_PUB_KEY,
			"de": DESTINATION_PUB_KEY,
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

	HASH_METHOD="SHA-512"

	def __init__(self)->None:
		self.chats={}
		self.connected=False

		self.start()

	def connect(self)->None:
		self.socket.connect((self.HOST, self.PORT))
		self.connected=True

	def listen(self)->str|None:
		received:bytes=self.socket.recv(self.MESSAGE_SIZE)

		if received: return received.decode(self.ENCODING)
		self.connected=False
		return None
	
	def receive(self, raw_data:str):
		data:dict=json.loads(raw_data)
		sender_key=rsa.PublicKey.load_pkcs1(bytes.fromhex(data["s"]),"DER")

	

	def send(self, receiver_key:str|None, text:str)->None:
		sender_key:str=self.public_key.save_pkcs1("DER").hex()
		timestamp:float=time.time()

		data:dict={"t":timestamp, "txt":text}
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
		return rsa.sign(message.encode(), self.private_key, self.HASH_METHOD).hex()
	
	# TODO: implement.
	def verify(self, message, signature, pub_key)->bool:
		try:
			rsa.verify(message, signature, pub_key)
			return True
		except Exception: return False

	def encrypt(self, receivers_pub_key, content:str)->str:
		return self.__encrypt_with_key(receivers_pub_key, content)

	def decrypt(self, sender_pub_key, content:str)->str:
		return self.__decrypt_with_key(sender_pub_key, content)

	def __encrypt_with_key(self, key, content:str)->str:
		if not key: return content

		cipher:bytes=rsa.encrypt(content.encode(self.ENCODING),key)
		return base64.b64encode(cipher).decode()

	def __decrypt_with_key(self, key, content:str)->str:
		return rsa.decrypt(base64.b64decode(content.encode(self.ENCODING)), key).decode()




	def login(self)->None:
		self.send(self.SERVER_KEY, self.sign(self.VERIFICATION_KEY))
		if not self.listen()=="ok":
			raise Exception("ERROR LOGGING IN")
		


	def start(self)->None:
		if not self.load_keys():
			self.gen_keys()

		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
			self.socket=sock
			self.connect()

			self.login()

			listener:Thread=Thread(target=self.listener)
			speaker:Thread=Thread(target=self.speaker)

			listener.start()
			speaker.start()

	def listener(self)->None:
		while self.connected:
			contents:str|None=self.listen()
			if contents: print("[]:", contents)
	
	def speaker(self)->None:
		while self.connected:
			message:str=input("> ")
			self.socket.sendall(message.encode())


if __name__=="__main__":
	c=Client()
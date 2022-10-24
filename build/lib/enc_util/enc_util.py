from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES

def pad(data, *, block_size=AES.block_size, unpad=False):
	assert block_size > 3, f"Block size {block_size} not supported"
	if type(data) == str:
		data = data.encode('utf-8')
	if not unpad:
		pad_len = block_size - len(data) % block_size
		pad = bytes([pad_len]) * pad_len
		return data + pad
	else:
		pad_len = data[-1]
		return data[:-pad_len]


def encrypt(key, data, *, nonce=None, tags=True, output="base64"):
	if type(data) == str:
		data = data.encode("utf-8")
	if type(key) == str:
		key = key.encode("utf-8")
	if type(nonce) == str:
		nonce = nonce.encode("utf-8")
	data, key = pad(data), pad(key)
	do_return_nonce = nonce == None

	if nonce == None:
		cipher = AES.new(key, AES.MODE_EAX)
		nonce = cipher.nonce
	else:
		cipher = AES.new(key, AES.MODE_EAX, nonce=pad(nonce))

	ciphertext, tag = cipher.encrypt_and_digest(data)

	if output == "base64":
		ciphertext = b64encode(ciphertext).decode().replace("=", "")
		nonce = b64encode(nonce).decode().replace("=", "")
		tag = b64encode(tag).decode().replace("=", "")
		if do_return_nonce and tags:
			return f"A${nonce}${tag}${ciphertext}" #A for ALL
		elif not do_return_nonce and tags:
			return f"T${tag}${ciphertext}" #T for TAG
		elif do_return_nonce and not tags:
			return f"N${nonce}${ciphertext}" #N for NONCE
		elif not do_return_nonce and not tags:
			return f"-${ciphertext}" #- for NEITHER
		
	elif output == "bytes":
		if do_return_nonce and tags:
			return b"A|$" + nonce + tag + ciphertext #A for ALL
		elif not do_return_nonce and tags:
			return b"T|$" + tag + ciphertext #T for TAG
		elif do_return_nonce and not tags:
			return b"N|$" + nonce + ciphertext #N for NONCE
		elif not do_return_nonce and not tags:
			return b"-|$" + ciphertext #- for NEITHER

	else:
		raise ValueError('Invalid output mode')


def decrypt(key, data, *, nonce=None, tags=True, output="str"):
	if type(data) == str: #NTC or TC format 
		data = data.split('$')
		mode = data[0]
		data = [b64decode(i+'==') for i in data[1:]]
		if mode == 'A':
			nonce, tag, ciphertext = data
		elif mode == 'T':
			tag, ciphertext = data
		elif mode == 'N':
			nonce, ciphertext = data
		elif mode == '-':
			ciphertext = data[0]
		else:
			raise ValueError('Unknown mode')
			
	elif type(data) == bytes:
		mode = data[0:3].decode('utf-8')
		data = data[3:]
		if mode == 'A~$':
			nonce, tag, ciphertext = data[0:16], data[16:32], data[32:]
		elif mode == 'T~$':
			tag, ciphertext = data[0:16], data[16:]
		elif mode == 'N~$':
			nonce, ciphertext = data[0:16], data[16:]
		elif mode == '-~$':
			ciphertext = data
		else:
			raise ValueError('Unknown mode')
	
	if type(key) == str:
		key = key.encode("utf-8")
	if type(nonce) == str:
		nonce = nonce.encode("utf-8")
		nonce = pad(nonce)
	
	key = pad(key)
	
	cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

	if tags:
		decrypted = cipher.decrypt_and_verify(ciphertext, tag)
	else:
		decrypted = cipher.decrypt(ciphertext)
		
	if output == "str":
		return pad(decrypted, unpad=True).decode("utf-8")
	else:
		return pad(decrypted, unpad=True)


if __name__ == "__main__":
	while True:
		i = input("[E]ncrypt/[D]ecrypt: ")[0].lower()
		if i == "e":
			print(encrypt(input("Key: "), input("Plaintext: ")))
		elif i == "d":
			print(decrypt(input("Key: "), input("Ciphertext: ")))

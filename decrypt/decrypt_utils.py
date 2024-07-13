import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from tqdm import tqdm
from math import ceil

def decrypt_file_aes(input_file, output_file, aes_key):
	key = aes_key
	with open(input_file, 'rb') as f:
		encrypted_data = f.read()
	
	iv = encrypted_data[:AES.block_size]
	ciphertext = encrypted_data[AES.block_size:]
	
	cipher = AES.new(key, AES.MODE_CFB, iv=iv)
	decrypted_data = cipher.decrypt(ciphertext)
	
	with open(output_file, 'wb') as f:
		f.write(decrypted_data)
		
def rsa_decrypt_file(encrypted_rsa_file, private_key_file):
	with open(encrypted_rsa_file, 'rb') as f:
		enc_data = f.read()
	
	with open(private_key_file, 'rb') as f:
		private_key = RSA.import_key(f.read())
	
	cipher_rsa = PKCS1_OAEP.new(private_key)
	
	# Decrypt AES-encrypted data in chunks
	chunk_size = private_key.size_in_bytes()
	total_chunks = ceil(len(enc_data) / chunk_size)

	decrypted_data = bytearray()
	with tqdm(total=total_chunks, desc="Decrypting with RSA by chunk", unit="chunk") as pbar:
		for i in range(0, len(enc_data), chunk_size):
			chunk = enc_data[i:i+chunk_size]
			decrypted_chunk = cipher_rsa.decrypt(chunk)
			decrypted_data.extend(decrypted_chunk)
			pbar.update(1)
	
	return bytes(decrypted_data)

def unshuffle_bytes(data, seed):
	random.seed(seed)
	byte_list = list(data)
	n = len(byte_list)
	swaps = []
	tqdm.write(f"Getting ready to unshuffle {n} bytes with seed {seed}")
	with tqdm(total=n-1, desc="Preparations to unshuffle", unit="byte") as pbar:
		for i in range(n-1, 0, -1):
			j = random.randint(0, i)
			swaps.append((i, j))
			pbar.update(1)
	
	# Reversing the shuffle
	with tqdm(total=len(swaps), desc="Unshuffling", unit="swap") as pbar:
		for i, j in reversed(swaps):
			byte_list[i], byte_list[j] = byte_list[j], byte_list[i]
			pbar.update(1)

	return bytes(byte_list)

def unshuffle_file(shuffled_file_path, unshuffled_file_path):
	# Load the seed and original file extension from the metadata file
	metadata_file = f"{shuffled_file_path}.metadata"
	with open(metadata_file, 'r') as meta_file:
		seed = int(meta_file.readline().strip())
		original_extension = meta_file.readline().strip()
	
	with open(shuffled_file_path, 'rb') as f:
		shuffled_data = f.read()
	
	unshuffled_data = unshuffle_bytes(shuffled_data, seed)
	
	with open(unshuffled_file_path, 'wb') as f:
		f.write(unshuffled_data)
	
	return original_extension
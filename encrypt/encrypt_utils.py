from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from hashlib import sha256
import random
from os import path, remove
from math import ceil
from tqdm import tqdm

def encrypt_file_with_aes(input_file, output_file, user_provided_key):
	key = user_provided_key
	cipher = AES.new(key, AES.MODE_CFB)
	iv = cipher.iv
	
	with open(input_file, 'rb') as f:
		plaintext = f.read()
	
	ciphertext = cipher.encrypt(plaintext)
	
	original_extension = path.splitext(input_file)[1]

	with open(output_file + original_extension, 'wb') as f:
		f.write(iv + ciphertext)

	return output_file + original_extension

def generate_rsa_key_pair(public_key_file, private_key_file):
	key = RSA.generate(2048)
	private_key = key.export_key()
	with open(private_key_file, 'wb') as f:
		f.write(private_key)
	
	public_key = key.publickey().export_key()
	with open(public_key_file, 'wb') as f:
		f.write(public_key)
		
def rsa_encrypt_file(aes_encrypted_file, rsa_encrypted_file, public_key_file):
	with open(public_key_file, 'rb') as f:
		public_key = RSA.import_key(f.read())
	
	cipher_rsa = PKCS1_OAEP.new(public_key)
	
	original_extension = path.splitext(aes_encrypted_file)[1]

	with open(aes_encrypted_file, 'rb') as f:
		aes_encrypted_data = f.read()
	
	# Encrypt AES-encrypted data in chunks due to RSA size limitation
	chunk_size = public_key.size_in_bytes() - 42  # For PKCS1_OAEP
	total_chunks = ceil(len(aes_encrypted_data) / chunk_size)

	with tqdm(total=total_chunks, desc="Encrypting with RSA by chunk", unit="chunk") as pbar:
		encrypted_data = bytearray()
		for i in range(0, len(aes_encrypted_data), chunk_size):
			chunk = aes_encrypted_data[i:i+chunk_size]
			encrypted_chunk = cipher_rsa.encrypt(chunk)
			encrypted_data.extend(encrypted_chunk)
			pbar.update(1)
	
	with open(rsa_encrypted_file + original_extension, 'wb') as f:
		f.write(encrypted_data)
	
	return rsa_encrypted_file + original_extension
	
def get_file_seed(file_path):
	hasher = sha256()
	with open(file_path, 'rb') as f:
		buf = f.read()
		hasher.update(buf)
	return int.from_bytes(hasher.digest()[:4], 'big')

def shuffle_bytes(data, seed):
	random.seed(seed)
	byte_list = list(data)
	n = len(byte_list)
	tqdm.write(f"Shuffling {n} bytes with seed {seed}")
	with tqdm(total=n, desc="Shuffling", unit="byte") as pbar:
		for i in range(n-1, 0, -1):
			j = random.randint(0, i)
			byte_list[i], byte_list[j] = byte_list[j], byte_list[i]
			pbar.update(1)
	return bytes(byte_list)

def remove_file(file_path):
	if path.exists(file_path):
		remove(file_path)
	else:
		print(f"The file {file_path} does not exist.")

def shuffle_file(file_path, shuffled_file_path):
	seed = get_file_seed(file_path)
	with open(file_path, 'rb') as f:
		file_data = f.read()
	
	shuffled_data = shuffle_bytes(file_data, seed)
	
	with open(shuffled_file_path, 'wb') as f:
		f.write(shuffled_data)
	
	# Save the seed and original file extension to a metadata file
	metadata_file = f"{shuffled_file_path}.metadata"
	original_extension = path.splitext(file_path)[1]
	with open(metadata_file, 'w') as meta_file:
		meta_file.write(f"{seed}\n{original_extension}")

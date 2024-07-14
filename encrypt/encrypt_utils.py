from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from hashlib import sha256
import random
from os import path, remove
from math import ceil
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

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
		
def rsa_encrypt_chunk(chunk_data):
    chunk, public_key_bytes = chunk_data
    public_key = RSA.import_key(public_key_bytes)  # Reconstruct the public key object
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(chunk)

def rsa_encrypt_file(aes_encrypted_file, rsa_encrypted_file, public_key_file):
    with open(public_key_file, 'rb') as f:
        public_key_bytes = f.read()  # Read the public key as bytes
    
    original_extension = path.splitext(aes_encrypted_file)[1]

    with open(aes_encrypted_file, 'rb') as f:
        aes_encrypted_data = f.read()
    
    chunk_size = RSA.import_key(public_key_bytes).size_in_bytes() - 42  # Adjust for PKCS1_OAEP padding
    chunks = [(aes_encrypted_data[i:i+chunk_size], public_key_bytes) for i in range(0, len(aes_encrypted_data), chunk_size)]
    
    with Pool(cpu_count()) as pool:
        encrypted_chunks = list(tqdm(pool.imap(rsa_encrypt_chunk, chunks), total=len(chunks), desc="Encrypting with RSA by chunk", unit="chunk"))

    with open(rsa_encrypted_file + original_extension, 'wb') as f:
        for chunk in encrypted_chunks:
            f.write(chunk)

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
    with tqdm(total=n, desc="Shuffling", unit="byte", leave=False, mininterval=0.5, dynamic_ncols=True) as pbar:
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
    
    # Splitting the data for multiprocessing
    chunk_size = len(file_data) // cpu_count()
    data_chunks = [file_data[i:i+chunk_size] for i in range(0, len(file_data), chunk_size)]
    
    with Pool(cpu_count()) as pool:
        shuffled_chunks = pool.starmap(shuffle_bytes, [(chunk, seed) for chunk in data_chunks])
    
    shuffled_data = b''.join(shuffled_chunks)
    
    with open(shuffled_file_path, 'wb') as f:
        f.write(shuffled_data)
    
    # Save the seed and original file extension to a metadata file
    metadata_file = f"{shuffled_file_path}.metadata"
    original_extension = path.splitext(file_path)[1]
    with open(metadata_file, 'w') as meta_file:
        meta_file.write(f"{seed}\n{original_extension}")
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from tqdm import tqdm
from math import ceil
from multiprocessing import Pool, cpu_count

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
		
def rsa_decrypt_chunk(data):
    chunk, private_key_bytes = data
    private_key = RSA.import_key(private_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(chunk)

def rsa_decrypt_file(encrypted_rsa_file, private_key_file):
    with open(encrypted_rsa_file, 'rb') as f:
        enc_data = f.read()
    
    with open(private_key_file, 'rb') as f:
        private_key_bytes = f.read()
    
    private_key = RSA.import_key(private_key_bytes)
    chunk_size = private_key.size_in_bytes()
    
    # Split the encrypted data into chunks
    chunks = [enc_data[i:i + chunk_size] for i in range(0, len(enc_data), chunk_size)]
    
    # Prepare data for multiprocessing, pairing each chunk with the private key bytes
    data_for_pool = [(chunk, private_key_bytes) for chunk in chunks]
    
    # Use multiprocessing to decrypt each chunk
    with Pool(cpu_count()) as pool:
        decrypted_chunks = list(tqdm(pool.imap(rsa_decrypt_chunk, data_for_pool), total=len(chunks), desc="Decrypting RSA chunks"))
    
    # Reassemble the decrypted data
    decrypted_data = b''.join(decrypted_chunks)
    
    return decrypted_data

def unshuffle_bytes(data, seed):
    random.seed(seed)
    byte_list = list(data)
    n = len(byte_list)
    with tqdm(total=n-1, desc="Unshuffling", unit="swap", leave=False, mininterval=0.5, dynamic_ncols=True) as pbar:
        swaps = [(i, random.randint(0, i)) for i in range(n-1, 0, -1)]
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
    
    # Splitting the data for multiprocessing
    chunk_size = len(shuffled_data) // cpu_count()
    data_chunks = [shuffled_data[i:i+chunk_size] for i in range(0, len(shuffled_data), chunk_size)]
    
    with Pool(cpu_count()) as pool:
        unshuffled_chunks = pool.starmap(unshuffle_bytes, [(chunk, seed) for chunk in data_chunks])
    
    unshuffled_data = b''.join(unshuffled_chunks)
    
    with open(unshuffled_file_path, 'wb') as f:
        f.write(unshuffled_data)
    
    return original_extension
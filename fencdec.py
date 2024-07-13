import typer
from encrypt.encrypt_utils import encrypt_file_with_aes, generate_rsa_key_pair, rsa_encrypt_file, shuffle_file, remove_file
from decrypt.decrypt_utils import unshuffle_file, rsa_decrypt_file, decrypt_file_aes
from os import getcwd

app = typer.Typer()

@app.command()
def encrypt(input_file, aes_key):
	print('Encrypting...')
	input_file = getcwd() + '/' + input_file
	aes_key = aes_key.encode('utf-8').ljust(32, b'\0')[:32]
	aes_done_file = encrypt_file_with_aes(input_file, 'aes_done', aes_key)
	generate_rsa_key_pair('public.pem', 'private.pem')
	rsa_done_file = rsa_encrypt_file(aes_done_file, 'rsa_done', 'public.pem')
	shuffle_file(rsa_done_file, 'shuffled.bin')
	remove_file(aes_done_file)
	remove_file(rsa_done_file)
	remove_file(input_file)
	remove_file('public.pem')
	print("Encryption and shuffling complete.")

@app.command()
def decrypt(input_file, aes_key, private_key):
	print('Decrypting...')
	input_file = getcwd() + '/' + input_file
	aes_key = aes_key.encode('utf-8').ljust(32, b'\0')[:32]
	private_key_file = getcwd() + '/' + private_key
	original_extension = unshuffle_file(input_file, 'unshuffled.bin')
	decrypted_aes_data = rsa_decrypt_file('unshuffled.bin', private_key_file)
	decrypted_aes_file = 'unshuffled.bin.aes'
	with open(decrypted_aes_file, 'wb') as f:
		f.write(decrypted_aes_data)
	decrypted_file =  getcwd() + '/' + 'decrypted' + original_extension
	decrypt_file_aes(decrypted_aes_file, decrypted_file, aes_key)
	remove_file('unshuffled.bin')
	remove_file(decrypted_aes_file)
	remove_file('shuffled.bin')
	remove_file('shuffled.bin.metadata')
	remove_file('private.pem')
	print("Decryption complete.")

if __name__ == "__main__":
	app()
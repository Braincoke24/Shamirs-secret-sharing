import sys
import os
import secrets
from sympy import isprime

BASE_ALPH = tuple('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
BASE_DICT = dict((c, v) for v, c in enumerate(BASE_ALPH))
BASE_LEN = len(BASE_ALPH)

def base_decode(string):
	num = 0
	for char in string:
		num = num * BASE_LEN + BASE_DICT[char]
	return num

def base_encode(num):
	"""Converts an integer to an alphanumeric string using base 62 encoding.

	Args:
		num (int): The integer to be encoded.

	Returns:
		str: The alphanumeric string representation of the integer.
	"""
	if not num:
		return BASE_ALPH[0]

	encoding = ''
	while num:
		num, rem = divmod(num, BASE_LEN)
		encoding = BASE_ALPH[rem] + encoding
	return encoding

class NonPrimeError(Exception):
	"""Custom exception raised when a number is unexpectedly not prime."""
	pass

class PrimeTooSmallError(Exception):
	"""Custom exception raised when a prime number is too small."""
	pass

def load_prime(filename, min_bit_length=256):
	"""Loads a prime number from a file and performs validation.

	Args:
		filename (str): The name of the file containing the prime number.
		min_bit_length (int, optional): The minimum bit length required for the loaded prime number. Defaults to 256.

	Raises:
		FileNotFoundError: If the specified file does not exist.
		ValueError: If the file contains an invalid number.
		NonPrimeError: If the loaded number is not prime.
		PrimeTooSmallError: If the loaded number is too small.
	
	Returns:
		int: The loaded prime number.
	"""
	try:
		with open(filename,'r') as file:
			prime = int(file.read())
			if prime.bit_length() < min_bit_length:
				raise PrimeTooSmallError(f'{prime} is too small. You have to provide a prime number with a bit length of at least {min_bit_length}.')
			if not isprime(prime):
				raise NonPrimeError(f'{prime} is not prime.')
			return prime
	except FileNotFoundError:
		print('Error: File "{}" not found.\n'.format(filename))
		exit(1)
	except ValueError:
		print('Error: Invalid number in file "{}".\n'.format(filename))
		exit(1)
	except NonPrimeError:
		print('Error: Number in file "{}" is not a prime number.\n'.format(filename))
		exit(1)
	except PrimeTooSmallError:
		print('Error: Number in file "{}" is too small. You have to provide a prime number with a bit length of at least {}.\n'.format(filename,min_bit_length))
		exit(1)

def gen(n,k,p):
	"""Generates a secret and corresponding keys for Shamir's Secret Sharing scheme.

	Args:
		n (int): The total number of shares to generate.
		k (int): The threshold number of shares required to reconstruct the secret.
		p (int): The prime number used for finite field operations.

	Raises:
		ValueError: If the threshold exceeds the number of generated keys.

	Returns:
		tuple: A tuple containing the secret and a list of keys.
	"""
	if n < k:
		raise ValueError(f'Threshold ({k}) exceeds number of generated keys ({n}).')

	secret = secrets.randbelow(p)
	coeff = [secrets.randbelow(p) for i in range(k-1)]

	def f(x):
		res = secret
		for i in range(k-1):
			res += coeff[i]*pow(x,i+1,p) % p
			res %= p
		return res
	
	X = [secrets.randbelow(p-1) + 1 for i in range(n)]
	if len(list(set(X))) != n:
		return gen(n,k,p)
	
	Y = [f(x) for x in X]
	
	secret = base_encode(secret)
	sep = '-'
	keys = [sep.join([str(n), str(k), base_encode(X[i]), base_encode(Y[i])]) for i in range(n)]

	return secret, keys

class NoKeyError(Exception):
	""""Custom exception raised when no key is found."""
	pass

class NotEnoughKeysError(Exception):
	""""Custom exception raised when the number of keys is below the threshold."""
	pass

def read_key_files(path):
	try:
		points = []
		l = 0
		# Determine n by finding the maximum number of key files present in the directory
		n = 0
		for filename in os.listdir(path):
			if filename.startswith('key') and filename[3:].isdigit():
				with open(path + filename,'r') as file:
					X = file.read().split('-')
					if len(X) != 4:
						raise ValueError(f'Invalid key in {path + filename}')
					try:
						n, k = int(X[0]), int(X[1])
					except:
						raise ValueError(f'Invalid key in {path + filename}')

		if n == 0:
			raise NoKeyError(f'No key file found in "{path}".')

		for i in range(1,n+1):
			try:
				with open(path + 'key' + str(i),'r') as file:
					X = file.read().split('-')
					if len(X) != 4:
						raise ValueError(f'Invalid key in {path + filename}')
					X = X[2:]
					points.append([base_decode(x) for x in X])
					l += 1
					print('key ' + str(i) + ' found')
			except:
				print('key ' + str(i) + ' not found')
		print(str(l) + '/' + str(k) + ' keys found')
		if l >= k:
			return points
		else:
			raise NotEnoughKeysError(f'Insufficient keys. Please provide at least ' + str(k-l) + ' more keys.')
	except NoKeyError:
		print('Error: No key files found in "{}".\n'.format(path))
		exit(1)
	except NotEnoughKeysError as e:
		print('Error: {}\n'.format(e))
		exit(1)

def lagrange_interpolation(points,p):
	l = len(points)
	X = [points[i][0] for i in range(l)]
	Y = [points[i][1] for i in range(l)]
	s = 0
	for i in range(l):
		prod = Y[i]
		for j in range(l):
			if j == i: continue
			prod = -X[j]*prod % p
			prod = prod*pow((X[i]-X[j]),-1,p) % p
		s += prod
		s %= p
	secret = base_encode(s)
	
	return secret

def generate_secret_and_keys():
	"""Generates secret and corresponding keys for Shamir's Secret Sharing scheme."""
	try:
		p = load_prime('prime')
		n = 5 # Number of shares
		k = 3 # Threshold number of shares required to reconstruct the secret
		secret, keys = gen(n,k,p)

		path = 'output/'
		for i in range(1,6):
			with open(path + 'key' + str(i),'w') as file:
				file.write(keys[i-1])
		
		with open(path + 'secret_gen','w') as file:
				file.write(secret)
		
		print('Success!')

	except (FileNotFoundError, ValueError, NonPrimeError, PrimeTooSmallError) as e:
		print("Error: {}\n".format(e))
		exit(1)

def retrieve_secret():
	"""Retrieves the secret using the provided keys and performs Lagrange interpolation."""
	try:
		p = load_prime('prime')
		path = 'output/'
		points = read_key_files(path)
		print('Beginning lagrange interpolation...')
		secret = lagrange_interpolation(points,p)
		print('Interpolation successful')
		print('Saving secret to file "' + path + 'secret"')
		with open(path + 'secret','w') as file:
			file.write(secret)
		print('Success!')
	except (FileNotFoundError, ValueError, NonPrimeError, PrimeTooSmallError,NoKeyError) as e:
		print("Error: {}\n".format(e))
		exit(1)

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print("Usage: python script.py [generate|retrieve]")
		exit(1)

	option = sys.argv[1]
	if option == "generate":
		generate_secret_and_keys()
	elif option == "retrieve":
		retrieve_secret()
	else:
		print("Invalid option. Use 'generate' or 'retrieve'.")

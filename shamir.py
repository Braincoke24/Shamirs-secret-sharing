import sys
import os
import secrets
from sympy import isprime

BASE_ALPH = tuple('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
BASE_DICT = dict((c, v) for v, c in enumerate(BASE_ALPH))
BASE_LEN = len(BASE_ALPH)

def base_decode(string):
	"""Converts an alphanumeric string to an integer using base 62 decoding.

	Args:
		string (str): The alphanumeric string to be decoded.

	Returns:
		int: The integer representation of the alphanumeric string.
	"""
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
		with open(filename, 'r') as file:
			prime = int(file.read())
			if prime.bit_length() < min_bit_length:
				raise PrimeTooSmallError(f'{prime} is too small. You have to provide a prime number with a bit length of at least {min_bit_length}.')
			if not isprime(prime):
				raise NonPrimeError(f'{prime} is not prime.')
			return prime
	except FileNotFoundError:
		raise FileNotFoundError(f'File \'{filename}\' not found.')
	except ValueError:
		raise ValueError(f'Invalid number in file \'{filename}\'.')
	except NonPrimeError:
		raise NonPrimeError(f'Number in file \'{filename}\' is not a prime number.')
	except PrimeTooSmallError:
		raise PrimeTooSmallError(f'Number in file \'{filename}\' is too small. You have to provide a prime number with a bit length of at least {min_bit_length}.')

def gen(n, k, p):
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
	coefficients = [secrets.randbelow(p) for _ in range(k-1)]

	def f(x):
		res = secret
		for i in range(k-1):
			res += coefficients[i] * pow(x, i+1, p) % p
			res %= p
		return res
	
	X = [secrets.randbelow(p-1) + 1 for _ in range(n)]
	if len(set(X)) != n:
		return gen(n, k, p)
	
	Y = [f(x) for x in X]
	
	secret = base_encode(secret)
	sep = '-'
	keys = [sep.join([str(n), str(k), base_encode(X[i]), base_encode(Y[i])]) for i in range(n)]

	return secret, keys

class NoKeyError(Exception):
	"""Custom exception raised when no key is found."""
	pass

class NotEnoughKeysError(Exception):
	"""Custom exception raised when the number of keys is below the threshold."""
	pass

def read_key_files(path):
	"""Reads the key files from the specified directory and returns the points.

	Args:
		path (str): The path to the directory containing key files.

	Raises:
		NoKeyError: If no key files are found in the directory.
		NotEnoughKeysError: If the number of keys is below the threshold.

	Returns:
		list: A list containing the points (pairs of x, y values) extracted from the key files.
	"""
	try:
		points = []
		l = 0
		n, k = 0, 0  # Initialize n and k
		for filename in os.listdir(path):
			if filename.startswith('key') and filename[3:].isdigit():
				with open(os.path.join(path, filename), 'r') as file:
					X = file.read().split('-')
					if len(X) != 4:
						raise ValueError(f'Invalid key in {filename}')
					try:
						n, k = map(int, X[:2])  # Read n and k from the key file
					except ValueError:
						raise ValueError(f'Invalid key in {filename}')

		if n == 0:
			raise NoKeyError(f'No key file found in \'{path}\'.')

		for i in range(1, n + 1):
			try:
				with open(os.path.join(path, f'key{i}'), 'r') as file:
					X = file.read().split('-')
					if len(X) != 4:
						raise ValueError(f'Invalid key in key{i}')
					X = X[2:]
					points.append([base_decode(x) for x in X])
					l += 1
					print(f'Key {i} found')
			except FileNotFoundError:
				print(f'Key {i} not found')

		print(f'{l}/{k} keys found')
		if l >= k:
			return points
		else:
			raise NotEnoughKeysError(f'Insufficient keys. Please provide at least {k-l} more keys.')
	except NoKeyError:
		raise NoKeyError(f'No key files found in \'{path}\'.')

def lagrange_interpolation(points, p):
	"""Performs Lagrange interpolation to retrieve the secret from the provided points.

	Args:
		points (list): A list containing the points (pairs of x, y values) used for interpolation.
		p (int): The prime number used for finite field operations.

	Returns:
		str: The secret retrieved using Lagrange interpolation.
	"""
	l = len(points)
	X = [points[i][0] for i in range(l)]
	Y = [points[i][1] for i in range(l)]
	s = 0
	for i in range(l):
		prod = Y[i]
		for j in range(l):
			if j == i:
				continue
			prod = -X[j] * prod % p
			prod = prod * pow((X[i] - X[j]), -1, p) % p
		s += prod
		s %= p
	secret = base_encode(s)
	
	return secret

def generate_secret_and_keys(n, k, path):
	"""Generates secret and corresponding keys for Shamir's Secret Sharing scheme.

	Args:
		n (int): The total number of shares to generate.
		k (int): The threshold number of shares required to reconstruct the secret.
		path (str): The path to save the generated keys.

	"""
	try:
		p = load_prime('prime')
		secret, keys = gen(n, k, p)

		for i, key in enumerate(keys, start=1):
			with open(os.path.join(path, f'key{i}'), 'w') as file:
				file.write(key)
		
		with open(os.path.join(path, 'secret_gen'), 'w') as file:
			file.write(secret)
		
		print('Success!')

	except (FileNotFoundError, ValueError, NonPrimeError, PrimeTooSmallError) as e:
		print(f'Error: {e}\n')
		exit(1)

def retrieve_secret(path):
	"""Retrieves the secret using the provided keys and performs Lagrange interpolation.

	Args:
		path (str): The path to read the key files and save the secret.

	"""
	try:
		p = load_prime('prime')
		points = read_key_files(path)
		print('Beginning Lagrange interpolation...')
		secret = lagrange_interpolation(points, p)
		print('Interpolation successful')
		path_secret = os.path.join(path, 'secret')
		print(f'Saving secret to file \'{path_secret}\'')
		with open(os.path.join(path, 'secret'), 'w') as file:
			file.write(secret)
		print('Success!')
	except (FileNotFoundError, ValueError, NonPrimeError, PrimeTooSmallError, NoKeyError) as e:
		print(f'Error: {e}\n')
		exit(1)

if __name__ == '__main__':
	usage_message = 'Usage: python shamir.py [generate|retrieve] [path]'
	if len(sys.argv) < 2:
		print(usage_message)
		exit(1)
	
	option = sys.argv[1]
	if option == 'generate':
		if (len(sys.argv) != 4) and (len(sys.argv) != 5):
			print('Usage: python shamir.py generate <n> <k> [path]')
			exit(1)
		n = int(sys.argv[2])
		k = int(sys.argv[3])
		path = sys.argv[4] if len(sys.argv) == 5 else 'output'  # Default path is 'output'
		generate_secret_and_keys(n, k, path)
	elif (len(sys.argv) != 2) and (len(sys.argv) != 3):
		print(usage_message)
		exit(1)
	elif option == 'retrieve':
		path = sys.argv[2] if len(sys.argv) == 3 else 'output'  # Default path is 'output'
		retrieve_secret(path)
	else:
		print('Invalid option. Use \'generate\' or \'retrieve\'.')

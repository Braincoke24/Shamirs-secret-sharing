import secrets
from sympy import isprime

BASE_ALPH = tuple('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
BASE_DICT = dict((c, v) for v, c in enumerate(BASE_ALPH))
BASE_LEN = len(BASE_ALPH)

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
	keys = [base_encode(X[i]) + '-' + base_encode(Y[i]) for i in range(n)]

	return secret, keys

def main():
	"""Main function for Shamir's Secret Sharing."""
	try:
		p = load_prime('prime')
		secret, keys = gen(5,3,p)

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

if __name__ == "__main__":
	# If this script is executed directly (not imported as a module),
	# then call the main() function to start the program.
	main()

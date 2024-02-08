import secrets
from sympy import isprime

BASE_ALPH = tuple('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
BASE_DICT = dict((c, v) for v, c in enumerate(BASE_ALPH))
BASE_LEN = len(BASE_ALPH)

# convert integer to alphanumeric string using base 62
def base_encode(num):
    if not num:
        return BASE_ALPH[0]

    encoding = ''
    while num:
        num, rem = divmod(num, BASE_LEN)
        encoding = BASE_ALPH[rem] + encoding
    return encoding

# Define custom exception to use when a number unexspectedly is not prime
class NonPrimeError(Exception):
	pass
# Define custom exception to use when a prime number is too small
class PrimeTooSmallError(Exception):
	pass

# Load prime number from file
def load_prime(filename):
	try:
		with open(filename,'r') as file:
			prime = int(file.read())
			if prime.bit_length() < 256:
				raise PrimeTooSmallError(f'{prime} is too small. You have to provide a prime number with a bit length of at least 256.')
			if not isprime(prime):
				raise NonPrimeError(f'{prime} is not prime.')
			return prime
	except FileNotFoundError:
		print('Error: File "{}" not found.'.format(filename))
		exit(1)
	except ValueError:
		print('Error: Invalid number in file "{}".'.format(filename))
		exit(1)
	except NonPrimeError:
		print('Error: Number in file "{}" is not a prime number.'.format(filename))
		exit(1)
	except PrimeTooSmallError:
		print('Error: Number in file "{}" is too small. You have to provide a prime number with a bit length of at least 256.'.format(filename))
		exit(1)

# generate secret and keys
def gen(n,k,p):
	if n < k:
		raise ValueError(f'Threshold ({k}) exceeds number of generated keys ({n}).')
	# generate random secret
	secret = secrets.randbelow(p)
	# generate random polynomial with the secret as y-intercept
	coeff = [secrets.randbelow(p) for i in range(k-1)]
	def f(x):
		res = secret
		for i in range(k-1):
			res += coeff[i]*pow(x,i+1,p) % p
			res %= p
		return res
	# generate n distinct random x-values
	X = [secrets.randbelow(p-1) + 1 for i in range(n)]
	if len(list(set(X))) != n:
		return gen(n,k,p)
	# generate y-values from x-values
	Y = [f(x) for x in X]
	# convert secret and keys to alphanumeric strings
	secret = base_encode(secret)
	keys = [base_encode(X[i]) + '-' + base_encode(Y[i]) for i in range(n)]

	return secret, keys

# load prime, generate secret and keys and write them to files
def main():
	try:
		# Load prime number from file
		p = load_prime('prime')
		# generate secret and keys
		secret, keys = gen(5,3,p)
		# write keys to files
		path = 'output/'
		for i in range(1,6):
			with open(path + 'key' + str(i),'w') as file:
				file.write(keys[i-1])
		# write secret to file
		with open(path + 'secret_gen','w') as file:
				file.write(secret)
		print('Success!')
	except (FileNotFoundError, ValueError) as e:
		print("Error: {}".format(e))
		exit(1)

main()
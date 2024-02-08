BASE_ALPH = tuple('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
BASE_DICT = dict((c, v) for v, c in enumerate(BASE_ALPH))
BASE_LEN = len(BASE_ALPH)

def base_decode(string):
	num = 0
	for char in string:
		num = num * BASE_LEN + BASE_DICT[char]
	return num

def base_encode(num):
	if not num:
		return BASE_ALPH[0]

	encoding = ''
	while num:
		num, rem = divmod(num, BASE_LEN)
		encoding = BASE_ALPH[rem] + encoding
	return encoding

with open('prime','r') as f:
	p = int(f.read())
points = []
l = 0
path = 'output/'
for i in range(1,6):
	try:
		with open(path + 'key' + str(i),'r') as f:
			X = f.read().split('-')
			points.append([base_decode(x) for x in X])
			l += 1
			print('key ' + str(i) + ' found')
	except:
		print('secret ' + str(i) + ' not found')
print(str(l) + '/3 secrets found')
if l >= 3:
	print('Beginning lagrange interpolation...')
	public = [points[i][0] for i in range(l)]
	private = [points[i][1] for i in range(l)]
	try:
		s = 0
		for i in range(l):
			prod = private[i]
			for j in range(l):
				if j == i: continue
				prod = -public[j]*prod % p
				prod = prod*pow((public[i]-public[j]),-1,p) % p
			s += prod
			s %= p
		s = base_encode(s)
		print('Interpolation successful')
		print('Saving output to file \'secret\'')
		with open(path + 'secret','w') as f:
			f.write(s)
		print('Success!')
	except:
		print('Some error occured. Maybe you tried to cheat?')
else:
	print('insufficient secrets. Please provide at least ' + str(3-l) + ' more secrets.')

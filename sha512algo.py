import hashlib

text = 'a'

m = hashlib.sha512(text.encode('UTF-8'))
print(m.hexdigest())




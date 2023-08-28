import swiftcrypt


"""
the salt function, simply generates a salt with 'length' being an arg.
the pool function, generates 'x' amount of salts, where x is an arg.
the estimate_entropy function, gives back the entropy of a 'salt' as an arg. 
"""

salt = swiftCrypt.Salts().generate_salt()
pool = swiftCrypt.Salts().generate_pool(10)
entropy = swiftCrypt.Salts().estimate_entropy(salt)

"""

Entropy is a concept from information theory that measures the randomness or uncertainty of a set of data.
In the context of cryptography and security,
entropy refers to the strength of randomness in cryptographic keys, passwords, and other secret values.

"""


print(f"Generated Salt: {salt}\n\n\nPool Generated Salts: {pool} \n\n\nEntropy of salt {salt}: {entropy}")
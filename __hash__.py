import swiftCrypt

password= "SwiftCrypt"


#! the salt method is not in the hash class, go to __salts__.py for this.
salt = swiftCrypt.Salts().generate_salt(14)

"""Given a password with a salt, we can generate a hashed password, that can be de-hashed using the same salt, go to __checker__.py for this."""
hashedPass = swiftCrypt.Hash().hash_password(password,salt)


print(salt, hashedPass)

def returnHash():
    return password, hashedPass, salt
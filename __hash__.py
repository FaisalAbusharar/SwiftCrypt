import swiftCrypt

password= "SwiftCrypt"

salt = swiftCrypt.Hash().generate_salt(14)
hashedPass = swiftCrypt.Hash().hash_password(password,salt)


print(salt, hashedPass)

def returnHash():
    return password, hashedPass, salt
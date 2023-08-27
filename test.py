from keys import Keys,dataTransform, Passwords



keys_instance = Keys()



key = keys_instance.advancedKey(alpha="abcdefghijklmnopqrstuvwxyz1234567890",
                                  length=24,
                                  dashes=True,
                                  dash_range=4,
                                  uppercase=False,
                                 dual_cases=True)


UUID = keys_instance.generateUUID()


keys_instance = dataTransform()

data = b"Hello, this is binary data."

encoded_base64 = keys_instance.encodeBase64(data)
decoded_base64 = keys_instance.decodeBase64(encoded_base64)

encoded_hex = keys_instance.encodeHex(data)
decoded_hex = keys_instance.decodeHex(encoded_hex)


data_to_erase = bytearray(b"Sensitive information to be erased.")


keys_instance.securelyEraseData(data_to_erase)


keys_instance = Passwords()

password = keys_instance.generatePassword()
advancedPassword = keys_instance.advancedPassword(
    alpha="abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*+__--",
                                  length=24,
                                  uppercase=False,
                                 dual_cases=True)


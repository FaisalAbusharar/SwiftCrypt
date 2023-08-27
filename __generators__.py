import swiftCrypt


"""generates a key. yeah that simple, also takes in arguments, hover over it to see"""
key = swiftCrypt.SecretGenerator().generate_key()

"""same thing as key but password-like"""
password = swiftCrypt.SecretGenerator().generate_password()

"""generates a uuid, takes no arugments"""
uuid = swiftCrypt.SecretGenerator().generate_uuid()

"""generates random chars and places in them a list, you can choose what characters are chosen by the alpha arg and the length/amt."""
char = swiftCrypt.SecretGenerator().generate_random_chars(alpha="abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*",length=5)

"""creates a key with more options to choose from, the alpha and dual cases are new."""
advancedKey = swiftCrypt.AdvancedGenerator().advanced_key(alpha="abcdefghijklmnopqrstuvwxyz1234567890",
                                                          length=24,
                                                          dashes=True,
                                                          dash_range=4,
                                                          uppercase=False,
                                                          dual_cases=True)

"""same as advanced key, but password-like aswell"""
advancedPassword = swiftCrypt.AdvancedGenerator().advanced_password(alpha="abcdefghijklmnopqrstuvwxyz1234567890",
                                                          length=24,
                                                          uppercase=False,
                                                          dual_cases=True)

print(f"{key}\n{password}\n{uuid}\n{char}\n{advancedKey}\n{advancedPassword}")
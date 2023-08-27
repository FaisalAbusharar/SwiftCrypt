import swiftCrypt



key = swiftCrypt.SecretGenerator().generate_key()
password = swiftCrypt.SecretGenerator().generate_password()
uuid = swiftCrypt.SecretGenerator().generate_uuid()
char = swiftCrypt.SecretGenerator().generate_random_chars(alpha="abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*",length=5)
advancedKey = swiftCrypt.AdvancedGenerator().advanced_key(alpha="abcdefghijklmnopqrstuvwxyz1234567890",
                                                          length=24,
                                                          dashes=True,
                                                          dash_range=4,
                                                          uppercase=False,
                                                          dual_cases=True)

advancedPassword = swiftCrypt.AdvancedGenerator().advanced_password(alpha="abcdefghijklmnopqrstuvwxyz1234567890",
                                                          length=24,
                                                          uppercase=False,
                                                          dual_cases=True)

print(f"{key}\n{password}\n{uuid}\n{char}\n{advancedKey}\n{advancedPassword}")
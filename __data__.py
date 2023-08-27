import swiftCrypt


"""Encode bytes using HEX format, and then de-code them, takes bytes as arguements"""
encodeHEX = swiftCrypt.DataTransformer().encode_hex(b"Hello this is a byte, encoded with HEX")
decodeHEX = swiftCrypt.DataTransformer().decode_hex(encodeHEX)

"""Encode bytes using base64 format, and then de-code them, takes bytes as arguements"""
encode64 = swiftCrypt.DataTransformer().encode_base64(b"Hello again, this is a byte, encoded with base64")
decode64 = swiftCrypt.DataTransformer().decode_base64(encode64)

"""attempts to securely erase data in a bytearray by overwriting its contents with random bytes.
This is a common technique used to prevent sensitive data from being recovered after it's no longer needed.

The idea is to overwrite the data with random values so that any previous information stored in the bytearray becomes effectively unrecoverable
The use of secrets.token_bytes ensures that cryptographically secure random bytes are used for overwriting."""

data = ["This is a list, and we are gonna remove it", "more values", 1, 4, "yep", "lol"]
Erase_Data = swiftCrypt.DataTransformer().securely_erase_data(data)


print(f"Encoding HEX: {encodeHEX},  Decoding HEX: {decodeHEX}\nEncoding Base64: {encode64}, Decoding Base64: {decode64} \nPast Data: {data} Erased Data: {Erase_Data}")
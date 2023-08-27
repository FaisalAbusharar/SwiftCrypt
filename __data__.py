import swiftCrypt

encodeHEX = swiftCrypt.DataTransformer().encode_hex(b"Hello this is a byte, encoded with HEX")
decodeHEX = swiftCrypt.DataTransformer().decode_hex(encodeHEX)

encode64 = swiftCrypt.DataTransformer().encode_base64(b"Hello again, this is a byte, encoded with base64")
decode64 = swiftCrypt.DataTransformer().decode_base64(encode64)

data = ["This is a list, and we are gonna remove it", "more values", 1, 4, "yep", "lol"]
Erase_Data = swiftCrypt.DataTransformer().securely_erase_data(data)


print(f"Encoding HEX: {encodeHEX},  Decoding HEX: {decodeHEX}\nEncoding Base64: {encode64}, Decoding Base64: {decode64} \nPast Data: {data} Erased Data: {Erase_Data}")
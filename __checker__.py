import swiftCrypt
import __hash__

password = "1pWS$swoRdw4@cW@$"

strength = swiftCrypt.Checker().check_password_strength(password,min_length=12,min_uppercase=3,min_lowercase=4,min_numbers=2,min_special=2,return_codes=False)

""" if return codes is True, this method will return 1,2,3,4,5
 basically
 


1: length
2: uppercase
3: lowercase
4: numbers
5: speical
 
 
Only runs if "return_codes" is true"""

if strength == 0:
    print("Strong password detected.")
else:
    print(f"Weak Password, err code: {strength}")
    
    
password, hashedPass, salt = __hash__.returnHash()

"""verifiedPass-args: actual password, the hashed version, and the salt used.""" 
verifiedPass = swiftCrypt.Checker().verify_password(password, hashedPass, salt)
print(verifiedPass)                             

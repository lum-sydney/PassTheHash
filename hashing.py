import secrets
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

MIN_SALT_BYTES = 16
_default_hasher = PasswordHasher() #PasswordHasher.hash() already generates its own salt when we dont generate_salt, we can use function for custom salt

#Generates random sequence to act as salt; returns a salt of desired byte length
#Params: length acts as the length of the desired salt, defaults to 16. 
#How long do you want the salt in bytes?
#Return type hint "->": this hints a the type that the function should be returning;Type Hints Are Not Enforced at Runtime
def generate_salt(length: int = MIN_SALT_BYTES) -> bytes:
    #Checks to make sure salt is not less than 16 bytes 
    if length < MIN_SALT_BYTES:
        #ValueError: python class, raise error with the message
        raise ValueError(f"Salt length must be at least {MIN_SALT_BYTES} bytes.")

    #token_bytes: asks systems OS random num generator for 'length' amount of random bytes
    #from the secrets module in python
    #the secrets modules is more secure than random (better suited ), because with random an attacker could begin to notice patterns and predict future values
    return secrets.token_bytes(length)


# Function hashes the password
#Params: password is passed as a string, salt passed as bytes, chooose a hasher? SHould retun string
#Can enter an optional custom byte as salt. use None to use the default salt genrater by argon2
def hash_password(password: str, salt: bytes | None = None, hasher: PasswordHasher | None = None,) -> str:
    #raise error when password is empty
    if not password:
        raise ValueError("Password cannot be empty.")

    ph = hasher or _default_hasher

    #if a salt is entered: make sure its not lower than the mininmum, then use the chosen hasher.hash function and hash the given password
    if salt is not None:
        if len(salt) < MIN_SALT_BYTES:
            raise ValueError(f"Salt length must be at least {MIN_SALT_BYTES} bytes.")
        return ph.hash(password, salt=salt)
    return ph.hash(password)
#the output is a single string containing: algorithm, salt, params, and hash digest (?)
#This string reveals metadata, not the password 



def verify_password(
    #the save argon2id string retrieve from where users are stored
    stored_hash: str,

    #password entered at time of login attempt
    candidate_password: str,

    #optional password hasher instance
    hasher: PasswordHasher | None = None,

    #expecting to return a bool
) -> bool:
    #if sting is empty return false beofre running a password check
    if not stored_hash or not candidate_password:
        return False

    #compares stored Hashed password with the entered password
    ph = hasher or _default_hasher
    try:
        return ph.verify(stored_hash, candidate_password)
    except (VerifyMismatchError, InvalidHashError):
        return False

# Checks Whether hash was created using the instance's parameters.
#Why? "whenever your argon2 params change, you should rehash your passwords at the next opportunity"
# graet for mentioning how systems change ans upgrade
def needs_rehash(
    stored_hash: str,
    hasher: PasswordHasher | None = None,
) -> bool:
    ph = hasher or _default_hasher
    return ph.check_needs_rehash(stored_hash)




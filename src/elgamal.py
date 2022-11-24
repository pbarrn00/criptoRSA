#ElGamal Implementation
import random
from funcs import (compute_block_size, power_mod, multiplicative_inverse)
from diffie_hellman import (diffie_primes)

def generate_public_key(p: int, g: int, ai: int) -> int:
    '''
    Generates a public key for ElGamal
    Parameters
    ----------
    p : int
        Prime number
    g : int
        Generator for G = Z/pZ*
    ai : int
        Private key
    Returns
    -------
    int
        Public key
    '''
    return power_mod(g, ai, p)

def elgamal_keygen(p: int, g: int) -> tuple:
    '''
    Generates a public and private key for ElGamal
    Parameters
    ----------
    p : int
        Prime number
    g : int
        Generator for G = Z/pZ*
    Returns
    -------
    tuple
        Public and private key
    '''
    ai = random.randint(2, p - 2)
    pb = generate_public_key(p, g, ai)
    return pb, ai

def elgamal_encrypt(by: bytes, p: int, g: int, pb: int) -> bytes:
    '''
    Encrypts a message using ElGamal
    Parameters
    ----------
    m : bytes
        Message to be encrypted
    p : int
        Prime number
    g : int
        Generator for G = Z/pZ*
    pb : int
        Public key
    Returns
    -------
    bytes
        Encrypted message
    '''
    block_size = compute_block_size()      # What is the block size?
    encrypted_block_size = block_size + 1
    
    last_size = len(by) % block_size    
    last_size = last_size or block_size

    encrypted = elgamal_conversion(by, k, g, p, pb, block_size)
    encrypted = [block.to_bytes(encrypted_block_size, byteorder="big") 
                 for block in encrypted]

    k = random.randint(2, p - 2)
    c1 = power_mod(g, k, p)
    c2 = (m * power_mod(pb, k, p)) % p
    return c1, c2

def elgamal_decrypt(c1: int, c2: int, p: int, ai: int) -> int:
    '''
    Decrypts a message using ElGamal
    Parameters
    ----------
    c1 : int
        First part of the encrypted message
    c2 : int
        Second part of the encrypted message
    p : int
        Prime number
    ai : int
        Private key
    Returns
    -------
    int
        Decrypted message
    '''
    m = (c2 * multiplicative_inverse(power_mod(c1, ai, p), p)) % p
    return m



def main():
    # Generate p, g and public key
    p, g = diffie_primes(10)
    pb, ai = elgamal_keygen(p, g)
    print("p: {}".format(p))
    print("g: {}".format(g))
    print("My Public Key: {}".format(pb))
    print("My Private Key: {}".format(ai))

    # Bob public key
    pb_bob = 0
    
    # Message and encoded message
    my_message = "Hello elgamal, un saludo De La Hera"
    my_message_encoded = my_message.encode('utf-8')
    m
    # Encrypt and decrypt a message
    c1, c2 = elgamal_encrypt(m, p, g, pb_bob)
    print("c1: {}".format(c1))
    print("c2: {}".format(c2))
    m = elgamal_decrypt(c1, c2, p, ai)
    print("m: {}".format(m))


if __name__ == "__main__":
    main()
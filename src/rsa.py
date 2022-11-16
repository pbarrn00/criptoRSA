# -*- coding: utf-8 -*-
"""
Created on Wed Nov  9 12:54:13 2022

@author: David
"""
import math
from decimal import Decimal
import warnings
from funcs import (
    blocks_from_bytes, power_mod, compute_block_size, bytes_from_block,
    estimate_k, bitlength, coprimes, random_probable_prime,
    multiplicative_inverse, random_odd_number_nbits
)

def rsa_keygen(nlen: int = 2048, e: int = 2 ** 16 + 1, tries : int = 30000
               ) -> tuple[tuple[int, int], int]:
    '''
    Compute public and private keys for RSA

    Parameters
    ----------
    nlen : int
        Number of bits of n
    e: int
        Public exponent.
    tries : int. Default is 30000
        The number of randomly generated numbers to be tested for p and q
        in each iteration.
        If a number of random numbers equal to tries is generated, raise an
        error.

    Returns
    -------
    (n, e), d:
        (n, e) is the public key and d the private key
    '''
    # This is a particularity of our implementation, we will see why
    if nlen < 8:
        raise ValueError("Number of bits of n must be greater than 8")
    # Why?
    if e % 2 != 1:
        raise ValueError("e should be odd")
        
    # We are not going to enforce these limits, but they are NIST's recommendations
    if e <= 2 ** 16 or e >= 2 ** 256:
        warnings.warn("exponent e should be an odd integer between 2 ** 16 and 2 ** 256, got {}".format(e))
    if nlen not in [2048, 3072]:
        warnings.warn("bitlen should be in [2048, 3072], got {}".format(nlen))
    
    # NIST restrictions to ensure p and q are big enough but not too close
    p_size = math.ceil(nlen / 2)
    q_size = nlen - p_size
    # Why these values?
    min_p = Decimal(2 ** (p_size - 1)) * Decimal(2).sqrt()
    min_q = Decimal(2 ** (q_size - 1)) * Decimal(2).sqrt()
    min_d = 2 ** (nlen // 2)
    p_q_diff = 2 ** (nlen // 2 - 100)
    
    # Ensure we mimimize the probabilities of error in the primality test
    k = estimate_k(nlen, 2 ** - 128)
    
    valid_d = False
    # d must not be too small and the number of bits of n must be exactly nlen
    # in accordance to NIST specifications
    while not valid_d:
        def valid_p(p_candidate):
            return p_candidate >= min_p and coprimes(p_candidate - 1, e)
        
        p = random_probable_prime(random_odd_number_nbits(p_size),
                                  k = k, test_func = valid_p,
                                  limit = tries)            
        
        def valid_q(q_candidate):
            return (
                q_candidate >= min_q
                and coprimes(q_candidate - 1, e)
                and abs(p - q_candidate) >= p_q_diff
            )
        
        q = random_probable_prime(random_odd_number_nbits(q_size), k = k, 
                                  test_func = valid_q, limit = tries)
        
        # Preserves properties of RSA and gives smaller values of d, 
        # which accelerates computations
        carmichael_lambda = math.lcm(p - 1, q - 1)
        d = multiplicative_inverse(e, carmichael_lambda)
        n = p * q
        
        # Check loop conditions
        valid_d = d > min_d
    return (n, e), d



def rsa_conversion(by: bytes, n: int, ex: int, extract_blocks_size: int
                   ) -> list[int]:
    '''
    Executes RSA exponentiation on bytes and returns the blocks

    Parameters
    ----------
    by : bytes
        Message to be processed
    n : int
        Public modulus
    ex : int
        The exponent
    extract_blocks_size : int
        Size of the blocks to be extracted from the message

    Returns
    -------
    list[int]
        Exponentiated blocks.

    '''
    blocks = blocks_from_bytes(by, extract_blocks_size)
    return [power_mod(block, ex, n) for block in blocks]
    


def rsa_encrypt(by: bytes, n: int, e: int) -> bytes:
    '''
    Encrypt a message using RSA

    Parameters
    ----------
    text : bytes
        Message to encrypt
    n: int
        Public modulus of receiver
    e : int
        Public exponent of receiver
    Returns
    -------
    bytes
        The encrypted message
    '''
    block_size = compute_block_size(n)
    encrypted_block_size = block_size + 1
    
    last_size = len(by) % block_size    
    last_size = last_size or block_size
    encrypted = rsa_conversion(by, n, e, block_size)
    encrypted = [block.to_bytes(encrypted_block_size, byteorder="big") 
                 for block in encrypted]
    
    # We add an additional block with size of the last one.
    # This is necessary to properly decrypt leading null bytes
    padding_block = rsa_conversion(
        last_size.to_bytes(block_size, byteorder="big"), n, e, block_size)
    padding_block = [block.to_bytes(encrypted_block_size, byteorder="big")
                     for block in padding_block]
    encrypted = (b'').join(encrypted + padding_block)
    return encrypted



def rsa_decrypt(by: bytes, n: int, d: int) -> bytes:
    '''
    Decrypt en encrypted message with RSA

    Parameters
    ----------
    text : str
        Encrypted text
    n : int
        Receiver public modulus
    d : int
        Receiver private key

    Returns
    -------
    str.
        The original message
    '''
    encrypted_block_size = compute_block_size(n) + 1
    
    decrypted = rsa_conversion(by, n, d, encrypted_block_size)
    last_size = decrypted[-1]
    
    # decrypt the last block independently
    last_block = [bytes_from_block(decrypted[-2], last_size)]
    
    decrypted = decrypted[:-2]
    decrypted = [bytes_from_block(block, encrypted_block_size - 1) 
                 for block in decrypted]
    decrypted = (b'').join(decrypted + last_block)
    
    return decrypted


if __name__ == "__main__":
    (n, e), d = rsa_keygen(25, 3)
    message = "s¨Gfç"
    message = "A: Смерть Ивана Ильича"
    enc = message.encode("utf-16")
    encrypted = rsa_encrypt(enc, n, e)
    orig = rsa_decrypt(encrypted, n, d)
    ori = orig.decode("utf-16")
    print(message)
    print(ori)

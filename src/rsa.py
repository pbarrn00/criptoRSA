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
    #k = estimate_k(nlen, 2 ** - 128)
    k=10

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

    # Generate keys
    #(n, e), d = rsa_keygen(25, 3)
    #(n, e), d = rsa_keygen(2048, 1048577) # 2 ** 20 + 1

    # My keys
    my_n = 26048554081918254772402396727078703502465630597557533117266018789540485475780747197584786190583271659321248729334208524047445737010919616936750858444125060319935027986793977486364471226442713933107427185696864514440603036987197122052742572277872232336254534169638265140240086157981444129651777094261637305372368382906823741917018463938809736866185156571482505798855621207493962046944957554996630201900999421476673956674245683880443049677156075409792647550985559524417635425479290915851823838059536484410257318950869021661885086295099873576476184621848777021277715499350226940503299366676306029946602286741170650381573
    my_e = 1048577
    d = 8218963619372557692910370685173757588806314476154927055346147062692628868106979050480147553042701294258555913965003579706731615304872009497402570357690150038548569994847074692005125073514891887001582620296057436250940461209132130711806558338852162323715363906602146812469387546685152118712836305956216115513645166176160379367790213854735464555181558968349118536807805876492651728335836742969901477132995724698537002827984322378797787447850240094657238846651355786074423434055493367106343372549149380884766894995811542324153769768606840351719414615414942624596654342120645031125422052336590868754335171446733398575793
    
    # Partner's public key
    n = 114356387938250571998855556339192452339978701019706434327536738880353463445842014974726846011663123968247759668222033442994457153716714114865508221205742264103814401941312467256286871980697932691266861717793914685855212352937386293306155340868414661068800196205964830601310053429265233106373511729057212442297
    e = 65537
    
    print("Public key: ", (n, e))
    print("Private key: ", d)

    # Encrypt message
    message = "P: Hello, De La Hero! How are you?"
    enc = message.encode("utf-16") # Cambiar a utf-8 en el próximo mensaje
    encrypted = rsa_encrypt(enc, n, e)

    # Decrypt message
    encryptedReceived = b'G\xcc\xa8YB\xcfR\xc6\x0ek\tnzc\x0c\xd0\xc1u\xb2\xcd5\xaf\x964\xe4\xa5\xfc\xf4O*\x94[>\xacy\x14B"\xbf\x81\xfc1\xa5\xd1\xa6PB\xba\xd2\xddZ\xe2\xc2p\xcc\x8b"\x08\xdek\x89\xbdPyr\xc7\xad\x91\x7f\xcb\xce\x1e\xa0O\xa2\x13g\xad\x85BF\x83|oH\x0e\xb1\xbd\x97\xee\x85qT\xd4\xab\n_\xc1A\xf7\xe7\x9b\xb1\x8bnYeF\xeffWX\xfa\x1f\xf5:\xce\xa2v\xe1\xc0 \x93\xab\xfc\xe0\xedh\x95\x1d\x9bh~\xcdW\xd0\xc6\xaa\xd3B\x1c\xf3f\xe5\n\x0e\xe1\x90\x87\xe5\x13\xa1\x04ZxpKb\xbfJ\xf3M-`\xd3\xfa\xc4\x0b\x02\xec\xd3\xa2\xf9\xd3`1\x08\xea\x8a\xe0\x91\xae@\xb4\xe3{VH3\xd5lY\xaa\xca\x95A\xf44\x13Z\x0c9\x8f\xc5C\xa2\x8aMd\xbbQ\x99\x80\xc3:t\xa8*\x11>19\x9b\xf3\xa2C\x8c\xa8\x1d\xac\xd6\xffj\rSR\x9f\xa5\xa7\xec\x89Vz&\xa6O\xb8#\x04\xe5\xb3|\xee%\xe31'
    orig = rsa_decrypt(encryptedReceived, my_n, d)
    ori = orig.decode("utf-8")

    # Print results  
    print("Original message: ", message)
    print("Encrypted message: ", encrypted)
    #print("Decrypted message: ", ori)

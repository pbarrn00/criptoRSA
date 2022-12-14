# -*- coding: utf-8 -*-
"""
Created on Tue Nov  22 13:08:44 2022

@author: Pablo Javier Barrio Navarro
"""
#ElGamal Implementation
import random
import secrets
from funcs import (block_from_bytes, blocks_from_bytes, bytes_from_block, compute_block_size, power_mod, multiplicative_inverse)
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
    my_pk = generate_public_key(p, g, ai)
    return my_pk, ai

def elgamal_encrypt(by: bytes, g: int, pk_bob: int, p: int) -> list[tuple[int, bytes]]:
    '''
    Encrypts a message using ElGamal
    Parameters
    ----------
    by : bytes
        Message to be encrypted
    g : int
        Generator for G = Z/pZ*
    k : int
        Random number
    pk_bob : int
        Public key of Bob
    p : int
        Prime number
    Returns 
    -------
    tuple[int, bytes]
        Encrypted message
    '''
    block_size = compute_block_size(p)
    encrypted_block_size = block_size + 1
    
    last_size = len(by) % block_size    
    last_size = last_size or block_size
    encrypted = elgamal_encryption(by, g, pk_bob, p, block_size)

    #print("Encrypted block: "+str(encrypted))
    encryptedC1 = []
    encryptedC2 = []
    
    for block in encrypted:
        encryptedC1.append(block[0])
        encryptedC2.append(block[1].to_bytes(encrypted_block_size, 'big'))

    #print("encrypted C1: "+str(encryptedC1))
    #print("encrypted C2: "+str(encryptedC2))
    
    #print("Encrypted block bytes: "+str(encrypted))

    
    # We add an additional block with size of the last one.
    # This is necessary to properly decrypt leading null bytes
    padding_block = elgamal_encryption(
        last_size.to_bytes(block_size, byteorder="big"), g, pk_bob, p, block_size)
    
    for block in padding_block:
        encryptedC1.append(block[0])
        encryptedC2.append(block[1].to_bytes(encrypted_block_size, 'big'))

    #print("padding_block C1: "+str(padding_blockC1))
    #print("padding_block C2: "+str(padding_blockC2))

    list = []
    for elementC1, elementC2 in zip(encryptedC1, encryptedC2):
        list.append((elementC1, elementC2))
    
    return list

def elgamal_encryption(by: bytes, g: int, pk_bob: int, p: int, extract_blocks_size: int
                   ) -> list[tuple[int, int]]:
    '''
    Encrypts a message using ElGamal
    Parameters
    ----------
    by : bytes
        Message to be encrypted
    g : int
        Generator for G = Z/pZ*
    pk_bob : int
        Public key of Bob
    p : int
        Prime number
    extract_blocks_size : int
        Size of the blocks to be extracted from the message
    Returns
    -------
    list[tuple[int, int]]
        Encrypted message
    '''

    blocks = blocks_from_bytes(by, extract_blocks_size)
    encryptions = []

    for block in blocks:
        key = secrets.choice(range(2, p-1))
        C1 = power_mod(g, key, p)
        C2 = (block*power_mod(pk_bob, key, p))%p
        encryptions.append((C1, C2))

    return encryptions

def elgamal_decrypt(by: bytes, p: int, ai: int) -> bytes:
    '''
    Decrypts a message using ElGamal
    Parameters
    ----------
    by : bytes
        Message to be decrypted
    p : int
        Prime number
    ai : int
        Private key
    Returns
    -------
    int
        Decrypted message
    '''
    decryptedC1 = []
    decryptedC2 = []
    for block in by:
        decryptedC1.append(block[0])
        decryptedC2.append(block[1])
    
    print("Decrypted C1: "+str(decryptedC1))
    print("Decrypted C2: "+str(decryptedC2))

    encrypted_block_size = compute_block_size(p) + 1

    decrypted = elgamal_decryption(decryptedC1, decryptedC2, ai, p)
    last_size = decrypted[-1]
    
    # decrypt the last block independently
    last_block = [bytes_from_block(decrypted[-2], last_size)]
    
    
    decrypted = decrypted[:-2]

    decrypted = [bytes_from_block(block, encrypted_block_size - 1) 
                 for block in decrypted]
    print("Decrypted bytes: "+str(decrypted))
    decrypted = (b'').join(decrypted + last_block)
    return decrypted

def elgamal_decryption(listC1: list, listC2: list, ai: int, p: int
                   ) -> list[int]:
    '''
    Decrypts a message using ElGamal
    Parameters
    ----------
    listC1 : list
        List of C1
    listC2 : list
        List of C2
    ai : int
        Private key
    p : int 
        Prime number
    Returns 
    -------     
    list[int]
        Decrypted message
    '''
    blocksC1 = []
    blocksC2 = []

    for elementC1, elementC2 in zip(listC1, listC2):
        blocksC1.append(elementC1)
        blocksC2.append(block_from_bytes(elementC2))        

    return [blockC2*multiplicative_inverse(power_mod(blockC1, ai, p), p)%p for blockC1, blockC2 in zip(blocksC1, blocksC2)]

def main():
    # Generate p, g and public key
    #p, g, k= diffie_primes(32)
    #my_pk, ai = elgamal_keygen(p, g)

    # Public key
    p = 28499
    g = 14249
    my_pk = 14249

    # My Private key
    ai = 44637
    
    print("p: {}".format(p))
    print("g: {}".format(g))
    print("My Public Key: {}".format(my_pk))
    print("My Private Key: {}".format(ai))

    # Bob's public key
    p_bob = 68507
    g_bob = 64136
    pk_bob = 44370
    
    # Message and encoded message
    my_message = "Hola muy buenas. Saludos desde mi casa"
    print("My message: {}".format(my_message))
    my_message_encoded = my_message.encode('utf-8')
    
    bob_encoded_message = [(9724, b'\x01\x02\xeb'), (65831, b'\x00\xa1('), (46342, b'\x00\xf1\x02'), (64677, b'\x00\x944'), (48420, b'\x00x\xcd'), (41638, b'\x00\x03\xe8'), (58577, b'\x00}\xd8'), (38141, b'\x00\x7f\xa0'), (38872, b'\x00\x98\x8f'), (29880, b'\x00\x82\xd1'), (33541, b'\x00\xb6\x00'), (51857, b'\x00\x14\xd7'), (45537, b'\x00\x7f\xb5'), (28820, b'\x00\xd2\xf4'), (48484, b'\x01\x04\xc8'), (23053, b'\x00 R'), (37668, b'\x00\x18\xab'), (37723, b'\x00\xf7:'), (23084, b'\x00\xae\xa5')]
    
    # Encrypt and decrypt a message
    encrypted = elgamal_encrypt(my_message_encoded, g_bob, pk_bob, p_bob)
    print("Encrypted: "+str(encrypted))

    decrypted = elgamal_decrypt(bob_encoded_message, p_bob, ai)
    message = decrypted.decode('utf-8')
    print("Bob Message Decrypted: "+str(message))

if __name__ == "__main__":
    main()
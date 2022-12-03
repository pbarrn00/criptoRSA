#ElGamal Implementation
import random
import secrets
from funcs import (blocks_from_bytes, bytes_from_block, compute_block_size, power_mod, multiplicative_inverse)
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

def elgamal_encrypt(by: bytes, g: int, k: int, pk_bob: int, p: int) -> tuple[int, bytes]:
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
        
    encryptedC1 = [block[0].to_bytes(encrypted_block_size, byteorder="big") 
                for block in encrypted]
    encryptedC2 = [block[1].to_bytes(encrypted_block_size, byteorder="big") 
                for block in encrypted]

    #print("encrypted C1: "+str(encryptedC1))
    #print("encrypted C2: "+str(encryptedC2))
    
    #print("Encrypted block bytes: "+str(encrypted))

    
    # We add an additional block with size of the last one.
    # This is necessary to properly decrypt leading null bytes
    padding_block = elgamal_encryption(
        last_size.to_bytes(block_size, byteorder="big"), g, pk_bob, p, block_size)
    padding_blockC1 = [block[0].to_bytes(encrypted_block_size, byteorder="big")
                     for block in padding_block]
    padding_blockC2 = [block[1].to_bytes(encrypted_block_size, byteorder="big")
                     for block in padding_block]

    #print("padding_block C1: "+str(padding_blockC1))
    #print("padding_block C2: "+str(padding_blockC2))

    encryptedC1 = (b'').join(encryptedC1 + padding_blockC1)
    encryptedC2 = (b'').join(encryptedC2 + padding_blockC2)
    return (encryptedC1, encryptedC2)

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
    key = secrets.choice(range(1, p-1))

    blocks = blocks_from_bytes(by, extract_blocks_size)
    encryptions = []

    for block in blocks:
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
    #print("Bytes: "+str(by))
    encrypted_block_size = compute_block_size(p) + 1

    decrypted = elgamal_decryption(by, ai, p, encrypted_block_size)
    #print("Decrypted: "+str(decrypted))
    last_size = decrypted[-1]
    
    # decrypt the last block independently
    last_block = [bytes_from_block(decrypted[-2], last_size)]
    
    decrypted = decrypted[:-2]
    decrypted = [bytes_from_block(block, encrypted_block_size - 1) 
                 for block in decrypted]
    #print("Decrypted bytes: "+str(decrypted))
    decrypted = (b'').join(decrypted + last_block)
    
    return decrypted

def elgamal_decryption(by, pk: int, p: int, extract_blocks_size: int
                   ) -> list[int]:

    blocksC1 = blocks_from_bytes(by[0], extract_blocks_size)
    blocksC2 = blocks_from_bytes(by[1], extract_blocks_size)
    C1 = blocksC1[0]

    return [block*multiplicative_inverse(power_mod(C1, pk, p), p)%p for block in blocksC2]

def main():
    # Generate p, g and public key
    p, g, k= diffie_primes(32)
    pb, ai = elgamal_keygen(p, g)
    print("p: {}".format(p))
    print("g: {}".format(g))
    print("My Public Key: {}".format(pb))
    print("My Private Key: {}".format(ai))

    # Bob public key
    pk_bob = pb
    
    # Message and encoded message
    my_message = "Hello Dela"
    print("My message: {}".format(my_message))
    my_message_encoded = my_message.encode('utf-8')
    
    # Encrypt and decrypt a message
    encrypted = elgamal_encrypt(my_message_encoded, g, k, pk_bob, p)
    print("Encrypted: "+str(encrypted))
    decrypted = elgamal_decrypt(encrypted, p, ai)
    message = decrypted.decode('utf-8')
    print("Decrypted: "+str(message))

if __name__ == "__main__":
    main()
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
    k = 12
    
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

    # =========================================================================== #
    # ================================= RSA KEYS ================================ #
    # =========================================================================== #
     # My keys
    barrio_n = 26048554081918254772402396727078703502465630597557533117266018789540485475780747197584786190583271659321248729334208524047445737010919616936750858444125060319935027986793977486364471226442713933107427185696864514440603036987197122052742572277872232336254534169638265140240086157981444129651777094261637305372368382906823741917018463938809736866185156571482505798855621207493962046944957554996630201900999421476673956674245683880443049677156075409792647550985559524417635425479290915851823838059536484410257318950869021661885086295099873576476184621848777021277715499350226940503299366676306029946602286741170650381573
    barrio_e = 1048577
    barrio_d = 8218963619372557692910370685173757588806314476154927055346147062692628868106979050480147553042701294258555913965003579706731615304872009497402570357690150038548569994847074692005125073514891887001582620296057436250940461209132130711806558338852162323715363906602146812469387546685152118712836305956216115513645166176160379367790213854735464555181558968349118536807805876492651728335836742969901477132995724698537002827984322378797787447850240094657238846651355786074423434055493367106343372549149380884766894995811542324153769768606840351719414615414942624596654342120645031125422052336590868754335171446733398575793
    
    # de la Hera's keys
    delahera_n = 102177145502170449647535015823292055188749752771393005649892105979200067597554948297407387457859709511918845152650987194391543702482122356296402530264892095093397819813676815413255338683528599712279533202539803336778869663204648825602128229440285623432111299318482515655843275628377999479423128550587755875503
    delahera_e = 65537

    #(n, e), d = rsa_keygen(1024)
    print("n:", barrio_n)
    print("e:", barrio_e)
    print("d:", barrio_d)
    print("")

    # =========================================================================== #
    # ============================ RSA ENCRYPTION =============================== #
    # =========================================================================== #

    message_barrio = "Hello, De La Hero! How are you?"
    enc_barrio = message_barrio.encode("utf-16") 
    encrypted_barrio = rsa_encrypt(enc_barrio, delahera_n, delahera_e)

    print("Mi mensaje en claro: ", message_barrio)
    print("Mi mensaje encriptado: ", encrypted_barrio)

    # =========================================================================== #
    # ============================ RSA DECRYPTION =============================== #
    # =========================================================================== #
    
    encrypted_delahera = b'CR\x9d"\x9d\x9c\x02d\xdeq)\x1a\xbc\x97\xe6\xd0\xea^!\xf1\xdet\xe2\xf5\xfbz\xa81\xe6\x06\xfd\x91\xd5q\xed\x0e&"\xf4{Uq%z1\xfa\xaf9\xaf\x85\xe9}%\xb5hH\xf3\x94\xc3\xaf}\r\xb9\x19\x9ff\x1d4\x0bc\xe1.\xff>XF9v\x08\x04\xdb\x04\xcd\x1f\x95BoP\xa3\x0c6\xb9\xadW\xb0~i\n\xe8\x8a\xe2\x02\x84+\xfb|\x97\x0f\x81\xf6\xd7\x92\xb3\x1f\xb7\xbe\x91\x9d*\xba\x119\xf1\x08`G\xe9\xa2|\xa8\x88\xc1\xb6\xd2\x1b\xd6\xd3IV\x9b\xeco\xff\x01H\xd08O\xb8\xe7n\xf1[2\x98\xf6-\x07/\x13\\\xb4$\xf7\xc1]2A\xbaR\xe3\xb4\xac\xb3w\x93\xed\x12~\xbbv\xf5$\xcb\xa0/\xcf\xe8\xcb\xcc\xec\xca\xf2\xf2\x95\xe6F\x9d\xec\xfd\xa1wA\x11\x980\x9f\x7fw\xa3\r\xa8\x15\xcb\xa1h\xae=R\xe8R\xee70z?\xe2\xd6=\xa2\xd986\xa6\x92j\x06\xb8w\xe9\xf1UI\x04\xaa\xff\x1c\x03\x05;!8\xe9\xe3\\\x93\x1f\x16=\xfb\x1e\xecT\x87\xbeP\x85\xa7\x90\xcc\x8a\x10\xb4\x03\xef\xfa\x0f\xac\xf2\xd7Ii@X\n\xb44\x9d*h\xc1\xd64`\xda\xd1\xa3\xe5\xac\x00Hrc\xc3\xb9Q\x1eCs\x80n\xc6\x86{\xdf\xa6\x8f\xf9\xe8\xa1`\xafV>\x98\\\xe2\xbb\xd4\xde\xfb%\x9d\xc9\x01\xa2\x00\xfd}(9\xa9=k\t\xd0\xb0L5\x1bo\xab\xfb(\x81\xd7\x8b\xac\xa2lLnr\xb0\x84\x7f\xed\x9fl\x8a\x90\xaa\xca\xb8\xdf7\xb5L\x95j\xb8"\xcej\xa6\\\x85\'\xf6\xbd\xb3\xc0\xb8\xd8\x1a@o\x03~Q\xc8\x822\xf2\\\xcd\xafm\t\xb8\xd2N\xa4\xad\xf9\\V5j\xb4\x80\xb3j\xe1n\xd3\rJA\xa5\xac\xccX\x02\x93I\xab\xaeV\xee\x93\x1dqqw\xdf\xecr\xa3\x8d\xaa\xb1zi@\xb76r\xe3y\x0e\xe1\xd0p\xd4/Dwg\xfb\x8b]\'\xb3p\x18\xcf]\xb3\xddr\xf7\x96s\xaf\xef`\xcc\x1a\xf0\xab\xd0{\xc1\xdcI\xed\xf49/\xb5R\x94\x17\x14\x9a\x07jX\xec\xfaQ'
    decrypted_delahera = rsa_decrypt(encrypted_delahera, barrio_n, barrio_d)

    print("\nMensaje de De La Hera: ", decrypted_delahera.decode("utf-16"))
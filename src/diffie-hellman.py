# Diffie-Hellman Implementation
# Implement a function to generate a random prime p of n bits and a random appropriate generator g for G = Z/pZ∗

import random
import math
import pi
from decimal import Decimal
from funcs import (
    blocks_from_bytes, power_mod, compute_block_size, bytes_from_block,
    estimate_k, bitlength, coprimes, random_probable_prime,
    multiplicative_inverse, random_odd_number_nbits
)

def diffie_primes(nlen: int) -> tuple[int, int]:
    # This is a particularity of our implementation, we will see why
    if nlen < 8:
        raise ValueError("Number of bits of n must be greater than 8")    

    # NIST restrictions to ensure p and q are big enough but not too close
    q_size = math.ceil(nlen / 2)
    
    # Ensure we mimimize the probabilities of error in the primality test
    #k = estimate_k(nlen, 2 ** - 128)
    k = 12

    valid_p = False

    while not valid_p: #comprobar que es es primo

        q = random_probable_prime(random_odd_number_nbits(q_size),
                                  k = k,
                                  limit = 50)

        p = (2 * q) + 1 
        if(is_prime(p)):
            valid_p = True
            print("Q y P son coprimos:{}".format(coprimes(q, p)))
            print(q, p)

    k = p-1
    g = generate_generator(p)

    return p,g
        
def generate_generator(p: int) -> int:
    '''
    Generates a generator for G = Z/pZ*
    Parameters
    ----------
    p : int
        Prime number
    Returns
    -------
    int
        Generator for G = Z/pZ*
    '''
    
    repetidos = list()
    for i in range(2, p-1):
        repetidos.append(i)

    g = random.choice(repetidos)

    while len(repetidos)!=0 and not is_generator(g, p):
        repetidos.remove(g)
        if len(repetidos)!=0:
            g = random.choice(repetidos)
        else:
            print("No existe generador")
    return g

def is_generator(g: int, p: int) -> bool:
    '''
    Checks if a number is a generator for G = Z/pZ*
    Parameters
    ----------
    g : int
        Number to be checked
    p : int
        Prime number
    Returns
    -------
    bool
        True if the number is a generator, False otherwise.
    '''
    if g < 2 or g >= p:
        return False
    for i in range(2, p):
        if power_mod(g, i, p) == 1:
            return False
    return True
  
def is_prime(n):
    '''
    Checks if a number is prime
    Parameters
    ----------
    n : int
        Number to be checked
    Returns
    -------
    bool
        True if the number is prime, False otherwise.
    '''
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n ** 0.5) + 1, 2):
        if n % i == 0:
            return False
    return True




    # =========================================================================== #
    # ============================== RFC FORMULA ================================ #
    # =========================================================================== #

def Diffie_HellmanRFC(n: int)-> tuple[int, int]:

    if(n != 1536):
        raise Exception("El número de bits debe ser 1536") 

    p = 2**1536 - 2**1472 - 1 + 2**64 * ( math.floor(2 ** 1406 * pi.approximate_pi(len(str(2**1406))-1))  + 741804 )

    g = 2

    return p,g


    # =========================================================================== #

if __name__ == '__main__':
    # 1. Generate two random primes of 1024 bits
    p, q = diffie_primes(32)
    print(f'p = {p}, q = {q}')

    # Part b) Generator pre-computed
    #print(f'g = {Diffie_HellmanRFC(1536)[1]}')
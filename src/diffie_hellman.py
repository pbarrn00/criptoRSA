# Diffie-Hellman Implementation
# Implement a function to generate a random prime p of n bits and a random appropriate generator g for G = Z/pZ∗

import random
import math
import pi
import warnings
from decimal import Decimal
from funcs import (
    power_mod, estimate_k, coprimes, random_probable_prime,
    random_odd_number_nbits, miller_rabin
)

    # =========================================================================== #
    #                                   PART a                                    #
    # =========================================================================== #

def diffie_primes(nlen: int, tries : int = 30000) -> tuple[int, int]:
    # This is a particularity of our implementation, we will see why
    if nlen < 8:
        raise ValueError("Number of bits of n must be greater than 8")    
    
    if nlen not in [2048, 3072]:
        warnings.warn("bitlen should be in [2048, 3072], got {}".format(nlen))


    # NIST restrictions to ensure p and q are big enough but not too close
    q_size = math.ceil(nlen / 2)                                                    # q_size = ???                      
    
    # Ensure we mimimize the probabilities of error in the primality test
    k = estimate_k(nlen, 2 ** - 128)

    valid_p = False

    while not valid_p: #comprobar que es es primo

        q = random_probable_prime(random_odd_number_nbits(q_size),
                                  k = k,
                                  limit = tries)

        p = (2 * q) + 1 
        
        if(miller_rabin(p, k)):
            valid_p = True
            print("Q y P son coprimos:{}".format(coprimes(q, p)))
            print(q, p)

    g = generate_generator(p)       # Here p is a prime number

    return p, g, k
        
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
    g = random.randint(2, p - 1)
    while not is_generator(g, p):
        g = random.randint(2, p - 1)
        
    print("Generador: {}".format(g))
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
    if g < 2 or g > p - 1:
        return False

    for n in range(1, p - 1):
        if power_mod(g, n, p) == 1:
            return False

    return True

    # =========================================================================== #
    #                                   PART b                                    #
    # =========================================================================== #

def Diffie_HellmanRFC(n: int)-> tuple[int, int]:

    if(n != 1536):
        raise Exception("El número de bits debe ser 1536") 

    p = 2**1536 - 2**1472 - 1 + 2**64 * ( math.floor(2 ** 1406 * pi.approximate_pi(len(str(2**1406))-1))  + 741804 )

    g = 2

    return p,g

    # =========================================================================== #
    #                                   PART c                                    #
    # =========================================================================== #

def common_key(p: int, ga: int) -> int:
    '''
    Computes the common key for both parties
    Parameters
    ----------
    p : int
        Prime number
    ga : int
        Public key for Alice
    Returns
    -------
    int
        Common key
    '''
    aB = random.randint(2, p - 2)
    return power_mod(ga, aB, p)


    # =========================================================================== #
    # =================================== MAIN ================================== #
    # =========================================================================== #

if __name__ == '__main__':
    # Part a) Implement a function to generate a random prime p of n bits and a random appropriate generator g for G = Z/pZ∗.
    p, g, k= diffie_primes(32)
    print("p: {} g: {}".format(p, g))

    # Part b) Implement a function that returns a pair of p and g obtained from RFC 3526
    p, g = Diffie_HellmanRFC(1536)
    print("p: {} g: {}".format(p, g))

    # Part c) Given p = 7883, g = 2 and a user with g^ai ≡ 1876 mod p, form a common key with that user.
    p = 7883
    ga = 1876
    k = common_key(p, ga)
    print("Common key for User: {}".format(k))

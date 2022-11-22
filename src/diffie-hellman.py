# Diffie-Hellman Implementation
# Implement a function to generate a random prime p of n bits and a random appropriate generator g for G = Z/pZ∗

import random

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

def random_prime(nbits: int) -> int:
    '''
    Generates a random prime of nbits bits

    Parameters
    ----------
    nbits : int
        Number of bits of the prime

    Returns
    -------
    int
        Random prime of nbits bits

    '''
    while True:
        candidate = random_odd_number_nbits(nbits)
        if is_prime(candidate):
            return candidate

def random_odd_number_nbits(nbits: int) -> int:
    '''
    Generates a random odd number of nbits bits

    Parameters
    ----------
    nbits : int
        Number of bits of the number

    Returns
    -------
    int
        Random odd number of nbits bits

    '''
    return random.randint(2 ** (nbits - 1), 2 ** nbits - 1) | 1

def generate_primes (nbits: int) -> tuple[int, int]:
    '''
    Generates two random primes of nbits bits

    Parameters
    ----------
    nbits : int
        Number of bits of the primes

    Returns
    -------
    tuple[int, int]
        Two random primes of nbits bits

    '''
    q = random_prime(nbits)
    p = 2*q + 1
    while p == q:
        q = random_prime(nbits)
    return p, q

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

def power_mod(a: int, b: int, m: int) -> int:
    '''
    Computes a^b mod m

    Parameters
    ----------
    a : int
        Base
    b : int
        Exponent
    m : int
        Modulus

    Returns
    -------
    int
        a^b mod m

    '''
    if b == 0:
        return 1
    if b == 1:
        return a % m
    if b % 2 == 0:
        return power_mod(a, b // 2, m) ** 2 % m
    return a * power_mod(a, b - 1, m) % m


if __name__ == '__main__':
    # 1. Generate two random primes of 8 bits
    p, q = generate_primes(8)
    print(f'p = {p}, q = {q}')

    # 2. Generate a generator for G = Z/pZ*
    g = generate_generator(p)
    print(f'g = {g}')
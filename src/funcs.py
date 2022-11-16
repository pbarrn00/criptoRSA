# -*- coding: utf-8 -*-
"""
Created on Tue Nov  8 12:08:58 2022

@author: David
"""
from typing import Iterable, Callable
import math
import secrets
from decimal import Decimal


def coprimes(a: int, b: int) -> bool:
    '''
    Tests whether a and b are coprimes

    Parameters
    ----------
    a : int
        A number.
    b : int
        Another number.

    Returns
    -------
    bool
        True if a and b are coprimes, False otherwise.
    '''
    return math.gcd(a, b) == 1

def iter_blocks(iterable: Iterable, n: int):
    '''
    Generator that returns blocks of size n from iterable. The last block may
    be truncated if the length of the iterable is not divisible by n

    Parameters
    ----------
    iterable : Iterable
        An iterable
    n : int
        Block size.

    Returns
    -------
    A generator that produces the blocks.

    '''
    if n <= 0:
        raise ValueError("n must be greater than 0")
    acum = []
    for elem in iterable:
        acum.append(elem)
        if len(acum) == n:
            yield acum
            acum = []
    if acum:
        yield acum
    

def power_mod(base: int, exp: int, m: int) -> int:
    '''
    Compute (base ** exp) % m

    Parameters
    ----------
    base : int
        Base
    power : int
        Exponent
    m : int
        Modulo

    Returns
    -------
    int
        Result
    '''
    return pow(base, exp, m)

def product_mod(a: int, b: int, m:int) -> int:
    '''
    Returns (a * b) % m

    Parameters
    ----------
    a : int
        Factor 1.
    b : int
        Factor 2.
    m : int
        Modulo.

    Returns
    -------
    int
        The product of a and b modulo m

    '''
    return (a * b) % m

def multiplicative_inverse(number: int, m: int = None) -> int:
    '''
    Computes (number ** -1) % modulo

    Parameters
    ----------
    number : int
        Number.
    modulo : int, optional
        The modulo. The default is None.

    Returns
    -------
    int
        The multiplicative inverse of number in modulo m

    '''
    return power_mod(number, -1, m)

def blocks_from_bytes(by: bytes, block_size: int) -> list:
    '''
    Transform text to a list of numeric blocks, based on number of bits in the
    key in order to encrypted.

    Parameters
    ----------
    by : bytes
        Plain text
    block_size : int
        Number of bytes per block

    Returns
    -------
    list
        A list of numeric blocks in which the plain text is encoded
    '''
    if block_size <= 0:
        raise ValueError("Block size must be an integer greater than zero")
        
    return [block_from_bytes(byte_block) 
            for byte_block in iter_blocks(by, block_size)]
    

def bitlength(n: int) -> int:
    '''
    Return the number of bits required to represent n

    Parameters
    ----------
    n : int
        number

    Returns
    -------
    int
        Number of bits to represent n
    '''
    return n.bit_length()


def compute_block_size(n: int) -> int:
    '''
    Computes the block size in bytes to be encrypted by RSA given the public
    modulus n.
    
    We want to compute blocks bytewise for simplicity, but RSA demands that the
    message be lower than n so the blocks to be encrypted must be of byte size
    such that the maximum representable value is lower than n.
    
    Conversely, the size of the already encrypted blocks in bytes must be such
    that it should accomodate any possible value in modulo n.
    
    In addition, we cannot use bytes_from_block since we want all blocks to be
    of the same size to make decryption more convenient
    
    For example in the length in bits of n is 12:
        Maximum representable value: 2 ** 12 - 1
        Minimum value: 2 ** 11 (The length in bits accounts for active bits)
        
        Since we want to work with bytes the blocks to be encoded as integers
        must have a maximum value lower than the minumum value. Therefore we select
        a block (byte) size of 1 since 2 ** 8 - 1 < 2 ** 11
        
        Once we have encrypted the blocks, they hold any value up to n - 1
        since we are working modulo n.
        We need an amount of bytes that can hold such a value. In this case
        it would be 2, since 2 ** 16 - 1 > n
        
    The size of the encrypted blocks will be block_size(n) + 1
    
    Parameters
    ----------
    n : int
        Public modulus

    Returns
    -------
    int
        The block size in bytes
    '''
    quotient, remainder = divmod(bitlength(n), 8)
    # If the bitlength of n is divisible by 8 we get an exact number of bytes
    # But there still is a possibility of getting a block value greater than n
    # so we restrict the block size to be a byte lower
    if remainder == 0:
        quotient -= 1
    return quotient


def miller_rabin(w: int, k: int = 10) -> bool:
    '''
    Computes the Miller-Rabin primality test for n. k is the number of rounds
    to be executed, a greater number increases the probability that n is actually
    prime is the test is positive.

    Parameters
    ----------
    w : int
        Number to be tested for primality.
    k : int, optional
        Number of rounds of the algorithm. The default is 32.

    Returns
    -------
    bool: whether n passes the test
    '''
    if w in [2, 3, 5, 7]:
        return True
    # If n is divisible by two do not bother with the algorithm: it is not prime
    if w % 2 == 0:
        return False
    a = 0
    m = w - 1
    while m % 2 == 0:
        a += 1
        m //= 2
    
    wlen = bitlength(w)
    for _ in range(k):
        b = secrets.randbits(wlen)
        while b <= 1 or b >= w - 1:
            b = secrets.randbits(wlen)
        z = power_mod(b, m, w)
        if z == 1 or z == w - 1:
            continue
        i = 0
        while i < a - 1 and z != 1:
            z = power_mod(z, 2, w)
            if z == w - 1:
                break
            i += 1
        else:
            return False
    return True


def estimate_k(bits: int, error : float = 2 ** -128) -> int:
    '''
    Compute the number of iterations of Miller-Rabin necessary to get a 
    probability of having a composite number with bits bits 
    passing the test lower than error.

    Parameters
    ----------
    bits : int
        Number of bits of the number to be tested
    error : TYPE, optional
        Upper bound on the probability of a composite number passing the test.
        The default is 2 ** -128.

    Returns
    -------
    int
        Number of iterations of Miller-Rabin.
    '''
    max_t = math.ceil(- math.log2(error) / 2)
    max_m = math.floor(2 * math.sqrt(bits - 1) - 1)
    for t in range(1, max_t):
        for M in range(3, max_m):
            first = Decimal(2.00743 * math.log(2) * bits) * pow(Decimal(2), -bits)
            summatory = sum(
                (
                    Decimal(2 ** (m - (m - 1) * t)) 
                    * sum(
                         Decimal(1 / Decimal(2) ** Decimal(j + (bits - 1) / j)) 
                         for j in range(2, m + 1)
                    )
                 )
                for m in range(3, M + 1)
            )
            summand = pow(Decimal(2), bits - 2 - M * t) 
            factor = (
                Decimal(8 * (math.pi ** 2 - 6) / 3) * pow(Decimal(2), bits - 2)
            )
            
            estimate = first * (summand + factor * summatory)
            if estimate < error:
                return t
    return max_t

def random_odd_number_nbits(nbits: int) -> Callable[[], int]:
    '''
    Returns a function that takes no arguments and returns a random odd number
    with nbits number of bits

    Parameters
    ----------
    nbits : int
        Number of bits

    Returns
    -------
    (Callable[[], int])
        Function that returns a random number
    '''
    return lambda: secrets.randbits(nbits) | 1

def random_number_range(low : int , high : int = None) -> Callable[[], int]:
    '''
    Returns a function that takes no arguments and returns a random number
    in a range.
    
    if only low is passed the range is [0, low)
    if low and high are passed the range is [low, high)

    Parameters
    ----------
    low : TYPE, optional
        The minimum value or the max if high is not passed. The default is None.
    high : TYPE, optional
        The high value. The default is None.

    Returns
    -------
    (Callable[[], int])
        The function that returns the random odd number in range
    '''
    if high is None:
        high = low
        low = 0
    return lambda: (secrets.randbelow(high - low) + low)


def random_probable_prime(generator_func: Callable[[], int], k: int = 50, 
                          test_func: Callable[[int], bool] = None,
                          limit: int = 30000) -> int:
    '''
    Generate a random prime number with a set number of bits 

    Parameters
    ----------
    bits : int
        Number of bits of the number
    k: int
        Number of iterations of Miller-Rabin test for primality
    test_func : Callable[[int], bool], optional
        Defines other criteria for acceptance of the random number.
        If the returned value is False the number is discarded
    limit : int
        Maximum number of randomly generated numbers to be tested.
        If no number satisfies the criteria, raise a ValueError


    Returns
    -------
    A random prime number of the desired number of bits

    '''
    test_func = (lambda x: True) if test_func is None else test_func

    i = 0     
    while True:
        random_number = generator_func()
        
        if test_func(random_number) and miller_rabin(random_number, k=k):
            return random_number
        if limit is not None:
            i += 1
            if i > limit:
                raise ValueError("Could not find a random number satisfying properties")
            
            

def to_base_factors(original: int, base: int = 2 ** 8) -> list[int]:
    '''
    Compute the coefficients of the decomposition of original in the selected
    base. Original is assumed to be decimal.
    
    The result is a list with the coefficients such that
    original = l[0] * base ** n + l[1] * base ** (n - 1), ..., l[n] * base ** 0

    Parameters
    ----------
    original : int
        The decimal value to transform
    base : int, optional
        The target base to convert original. The default is 2 ** 8.

    Returns
    -------
    list[int]
        The factors
    '''
    factors = []
    while original > 0:
        original, remainder = divmod(original, base)
        factors.insert(0, remainder)
    return factors

def from_base_factors(factors: Iterable[int], base: int = 2 ** 8) -> int:
    '''
    Compute decimal value from coefficients located in factors in the selected
    base.
    
    The result is an integer whose value is
    factors[0] * base ** 0 + factors[1] * base ** 1, ..., factors[n] * base ** n

    Parameters
    ----------
    factors : Iterable[int]
        The coefficients in the base
    base : int, optional
        The base of the factors. The default is 2 ** 8.

    Returns
    -------
    int
        The decimal value

    '''
    total = 0
    nfactors = len(factors)
    for i, factor in enumerate(factors):
        total += factor * base ** (nfactors - i - 1)
    return total


def bytes_from_block(block: int, blocksize : int = None) -> bytes:
    '''
    Extract the original bytes from a numeric block.
    Bytes are in big endian.

    Parameters
    ----------
    block : int
        Numeric value of a block
    blocksize: int
        The number of bytes in the block. Optional, default: None.

    Returns
    -------
    bytes
        The original bytes
    '''
    factors = to_base_factors(block, 2 ** 8)
    # deal with the null byte \x00 in the leftmost byte
    if blocksize is not None:
        factors = [0] * (blocksize - len(factors)) + factors
    return bytes(factors)


def block_from_bytes(byt: bytes) -> int:
    '''
    Translate the bytes to a numeric value in base 2 ** 8.
    Bytes are taken in little endian.
    
    Parameters
    ----------
    byt : bytes
        Bytes to transform
    base: 
    Returns
    -------
    int
        Numeric value of the bytes

    '''
    return from_base_factors(byt, 2 ** 8)

if __name__ == "__main__":
    by = b"\x00\x00\x01"
    b = block_from_bytes(by)
    by2 = bytes_from_block(b)
    by2 = bytes_from_block(b, 3)
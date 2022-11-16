from decimal import Decimal, getcontext

def approximate_pi(precision: int) -> Decimal:
    """Compute Pi to precision number of decimals.
    
    Taken from https://docs.python.org/3/library/decimal.html#recipes
    
    Changes the precision of Decimal's context to accomodate precision, 
    so beware

    Arguments
    ---------
    precision: int
        Number of significant digits
    
    Returns
    -------
    Decimal
        The approximation of the value of pi
    """
    getcontext().prec = precision + 1
    getcontext().prec += 2  # extra digits for intermediate steps
    three = Decimal(3)      # substitute "three=3.0" for regular floats
    lasts, t, s, n, na, d, da = 0, three, 3, 1, 0, 0, 24
    while s != lasts:
        lasts = s
        n, na = n+na, na+8
        d, da = d+da, da+32
        t = (t * n) / d
        s += t
    getcontext().prec -= 2
    return +s               # unary plus applies the new precision

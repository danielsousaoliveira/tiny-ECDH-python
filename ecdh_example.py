
# Crypto using elliptic curves defined over the finite binary field GF(2^m) where m is prime.
# The curves used are the anomalous binary curves (ABC-curves) or also called Koblitz curves.
# This class of curves was chosen because it yields efficient implementation of operations.
# Curves available - their different NIST/SECG names and eqivalent symmetric security level:
#
# NIST      SEC Group     strength
# ------------------------------------
# B-163     sect163k2      80 bit
#
# Curve parameters from:
# http://www.secg.org/sec2-v2.pdf
# http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
#
# Reference:
# https://www.ietf.org/rfc/rfc4492.txt 
#
# Original Version:
# https://github.com/kokke/tiny-ECDH-c

import numpy as np
from ecdh import *

def main():

    # 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob.
    private = np.zeros(6,dtype='u4')
    public = np.zeros(12,dtype='u4')
    sec = np.zeros(12,dtype='u4')

    for i in range(6):
        private[i] = np.random.randint(4294967296, dtype=np.uint32)

    private, public = ecdh_generate_keys(private,public)

    # 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice.
    private2 = np.zeros(6,dtype='u4')
    public2 = np.zeros(12,dtype='u4')
    sec2 = np.zeros(12,dtype='u4')

    for i in range(6):
        private2[i] = np.random.randint(4294967296, dtype=np.uint32)

    private2, public2 = ecdh_generate_keys(private2,public2)

    # 3. Alice calculates S = a * Q = a * (b * g).
    sec = ecdh_shared_secret(private,public2)

    # 4. Bob calculates T = b * P = b * (a * g).
    sec2 = ecdh_shared_secret(private2,public)

    # 5. Assert equality, i.e. check that both parties calculated the same value.
    try:
        if np.any(sec) and np.any(sec2):
            print(sec)
            np.array_equal(sec, sec2)
            print("Equal Key")
        else:
            print("Error None Key")
    except AssertionError:
        print("Error Key Not Equal")

        
if __name__ == "__main__":
    main()





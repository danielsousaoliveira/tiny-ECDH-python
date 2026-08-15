
# Crypto using an elliptic curve defined over the finite binary field GF(2^m).
# The implemented curve is NIST B-163, also known as SECG sect163r2.
# Its parameters are specified in SEC 2, section 3.2.3:
# https://www.secg.org/sec2-v2.pdf
# This B-163 ECDH implementation is below current security-strength
# requirements, is no longer approved for general use, and is limited to
# legacy use.
#
# Reference:
# https://www.ietf.org/rfc/rfc4492.txt 
#
# Original Version:
# https://github.com/kokke/tiny-ECDH-c

import numpy as np
from utils import *

# -------------------------------------------------------------------
# Elliptic Curve Diffie-Hellman key exchange protocol.
# -------------------------------------------------------------------

def ecdh_generate_keys(private_key, public_key):

    """ Generate public key based on a random private key defined earlier

    Returns:
        np.uint32[]: Clear private key
        np.uint32[]: Associated public key
    """

    # Get copy of "base" point 'G'
    pub1, pub2 = gf2point_copy(public_key[:6],public_key[6:],base_x,base_y) 

    # Abort key generation if random number is too small
    if bitvec_degree(private_key) < (CURVE_DEGREE // 2):
        return None, None
    else:
        nbits = bitvec_degree(base_order)
        for i in range(nbits - 1, BITVEC_NWORDS * 32):

            # Clear bits > CURVE_DEGREE in highest word to satisfy constraint 1 <= exp < n 
            private_key = bitvec_clr_bit(private_key, i)

        # Multiply base-point with scalar (private-key)
        pub1,pub2 = gf2point_mul(pub1,pub2,private_key)
        public_key = np.append(pub1,pub2)

        return private_key, public_key

def ecdh_shared_secret(private_key, others_pub):

    """ Calculate shared key between two parties 
    
    Returns:
        np.uint32[]: Shared key
    """

    output = np.zeros(12,dtype='u4')
    others1 = others_pub[:6]
    others2 = others_pub[6:]

    # Do some basic validation of other party's public key
    if not gf2point_is_zero(others1,others2) and gf2point_on_curve(others1,others2):
        for i in range(12):

            # Copy other side's public key to output
            output[i] = others_pub[i]

        # Multiply other side's public key with own private key
        others1,others2 = gf2point_mul(others1, others2, private_key)
        output = np.append(others1,others2)

        return output
    else:
        return None

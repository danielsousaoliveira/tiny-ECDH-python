"""Educational ECDH implementation for the NIST B-163 curve."""

from ._version import __version__
from .ecdh import ecdh_generate_keys, ecdh_shared_secret

__all__ = ["__version__", "ecdh_generate_keys", "ecdh_shared_secret"]

# This file is part of rah-sha256-hasher, an example handler for rah.
# Copyright (c) Board of Regents of the University of Wisconsin System
# Distributed under the MIT license; see LICENSE in the project root.

"""An example rah handler that writes the SHA-256 of a message field into REDCap."""

from rah_sha256_hasher.handler import hash_field

__all__ = ["hash_field"]

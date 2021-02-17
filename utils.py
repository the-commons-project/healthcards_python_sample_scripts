import zlib
import requests
from jose import jwk as jose_jwk
import json

## https://stackoverflow.com/a/1089787
def deflate(data, compresslevel=9):
    compress = zlib.compressobj(
        compresslevel,        # level: 0-9
        zlib.DEFLATED,        # method: must be DEFLATED
        -zlib.MAX_WBITS,      # window size in bits:
                                #   -15..-8: negate, suppress header
                                #   8..15: normal
                                #   16..30: subtract 16, gzip header
        zlib.DEF_MEM_LEVEL,   # mem level: 1..8/9
        0                     # strategy:
                                #   0 = Z_DEFAULT_STRATEGY
                                #   1 = Z_FILTERED
                                #   2 = Z_HUFFMAN_ONLY
                                #   3 = Z_RLE
                                #   4 = Z_FIXED
    )
    deflated = compress.compress(data)
    deflated += compress.flush()
    return deflated

def inflate(data):
    ## needed to add `-zlib.MAX_WBITS` here due to 
    ## zlib.error: Error -3 while decompressing data: incorrect header check
    decompress = zlib.decompressobj(
            -zlib.MAX_WBITS  # see above
    )
    inflated = decompress.decompress(data)
    inflated += decompress.flush()
    return inflated


def resolve_key_from_issuer(iss, kid, algorithm):

    r = requests.get(f'{iss}/.well-known/jwks.json')
    r.raise_for_status()

    jwks = r.json()

    for key in jwks['keys']:
        if kid == key.get('kid'):
            return jose_jwk.construct(key, algorithm)

    raise Exception(f'Key with kid = {kid} not found')

def resolve_key_from_file(jwks_filename, kid, algorithm):

    with open(jwks_filename, 'r', newline='') as jwks_file:
        jwks = json.load(jwks_file)

    for key in jwks['keys']:
        if kid == key.get('kid'):
            return jose_jwk.construct(key, algorithm)

    raise Exception(f'Key with kid = {kid} not found')

def load_private_key_from_file(jwks_filename, use, algorithm):
    with open(jwks_filename, 'r', newline='') as jwks_file:
        jwks = json.load(jwks_file)

    for key in jwks['keys']:
        if algorithm == key.get('alg') and use == key.get('use'):
            return (key.get('kid'), jose_jwk.construct(key, algorithm))

    raise Exception(f'Key with use = {use} algorithm = {algorithm} not found')




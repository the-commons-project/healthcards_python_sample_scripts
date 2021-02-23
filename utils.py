import zlib
import requests
from jose import jwk as jose_jwk, jws
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


def resolve_key_from_issuer():

    def resolve(iss, kid, algorithm):
        r = requests.get(f'{iss}/.well-known/jwks.json')
        r.raise_for_status()

        jwks = r.json()

        for key in jwks['keys']:
            if kid == key.get('kid'):
                return jose_jwk.construct(key, algorithm)

        raise Exception(f'Key with kid = {kid} not found')

    return resolve

def resolve_key_from_file(jwks_filename):
    def resolve(iss, kid, algorithm):
        with open(jwks_filename, 'r', newline='') as jwks_file:
            jwks = json.load(jwks_file)

        for key in jwks['keys']:
            if kid == key.get('kid'):
                return jose_jwk.construct(key, algorithm)

        raise Exception(f'Key with kid = {kid} not found')

    return resolve

def load_private_key_from_file(jwks_filename, use, algorithm):
    with open(jwks_filename, 'r', newline='') as jwks_file:
        jwks = json.load(jwks_file)

    for key in jwks['keys']:
        if algorithm == key.get('alg') and use == key.get('use'):
            return (key.get('kid'), jose_jwk.construct(key, algorithm))

    raise Exception(f'Key with use = {use} algorithm = {algorithm} not found')

def _decode_vc(jws_raw, key_resolver):
    ## before we can verify the vc, we first need to resolve the key
    ## the key ID is stored in the header
    ## Per the health cards IG,
    ## "Issuers SHALL publish keys as JSON Web Key Sets (see RFC7517), available at <<iss value from Signed JWT>> + .well-known/jwks.json"
    ## therefore, we need decode the claims to get the iss value in order to resolve the key
    ## The claims are compressed via Deflate, so decompress the data
    ## then, extract the iss claim to get access to the base URL, use that to resolve key with id = kid
    ## then, verify the jws
    unverified_headers = jws.get_unverified_headers(jws_raw)

    ## we expect data to be zipped, so deflate the data
    if unverified_headers.get('zip') == 'DEF':
        unverfied_claims_zip = jws.get_unverified_claims(jws_raw)
        raw_data = inflate(unverfied_claims_zip)
        data = json.loads(raw_data)
    else:
        raise Exception('Expecting payload to be compressed')

    iss = data['iss']
    kid = unverified_headers['kid']
    
    key = key_resolver(iss, kid, 'ES256')

    verified_jws = jws.verify(jws_raw, key, algorithms='ES256')
    payload = json.loads(inflate(verified_jws))
    return payload

def decode_vc(jws_raw):
    resolver = resolve_key_from_issuer()
    return _decode_vc(jws_raw, resolver)

def decode_vc_from_local_issuer(jws_raw, jwks_file):
    resolver = resolve_key_from_file(jwks_file)
    return _decode_vc(jws_raw, resolver)




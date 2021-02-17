from jose import jws
import json
import argparse
import base64
import utils

def decode_vc(jws_raw):

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
        raw_data = utils.inflate(unverfied_claims_zip)
        data = json.loads(raw_data)
    else:
        raise Exception('Expecting payload to be compressed')

    iss = data['iss']
    kid = unverified_headers['kid']

    key = utils.resolve_key_from_issuer(iss, kid, 'ES256')
    # key = utils.resolve_key_from_file('./jwks.json', kid, 'ES256')

    verified_jws = jws.verify(jws_raw, key, algorithms='ES256')
    payload = json.loads(utils.inflate(verified_jws))
    return payload

def main():
    parser = argparse.ArgumentParser(description='Decodes a vc')
    parser.add_argument('input', help='Input resource')
    args = parser.parse_args()

    try:
        jws_raw = base64.standard_b64decode(args.input).decode(encoding='utf-8')
        print("Base 64 decoding succeeded")
    except:
        print("Base 64 decoding failed, assuming input is JWS")
        jws_raw = args.input

    payload_dict = decode_vc(jws_raw)

    print(json.dumps(payload_dict, indent=4))

if __name__ == "__main__":
    main()
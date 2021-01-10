from did.did_service import DIDService
from did.did import DIDPublicKeyDocument
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode
import json
import argparse
import base64

did_service = DIDService()

def get_did_from_header(jws_raw):
    ##instantiate a JWS object
    jwstoken = jws.JWS()

    ##import the data into the JWS object
    jwstoken.deserialize(jws_raw)

    ##based on the JWS header, resolve the public signing key to be used for verification
    kid = jwstoken.jose_header.get('kid')
    split = kid.split("#")
    did = split[0]
    return did

def decode_vc(jws_raw):
    ##instantiate a JWS object
    jwstoken = jws.JWS()

    ##import the data into the JWS object
    jwstoken.deserialize(jws_raw)

    ##based on the JWS header, resolve the public signing key to be used for verification
    kid = jwstoken.jose_header.get('kid')
    key = did_service.resolve_key(kid)
    
    ##load the JWK into a useable key
    verifier_key = jwk.JWK.from_json(json.dumps(key))

    ##verify the payload
    jwstoken.verify(verifier_key)
    return jwstoken

def main():
    parser = argparse.ArgumentParser(description='Decodes a vc using the supplied DID config')
    parser.add_argument('input', help='Input resource')
    args = parser.parse_args()

    try:
        jws_raw = base64.standard_b64decode(args.input).decode(encoding='utf-8')
        print("Base 64 decoding succeeded")
    except:
        print("Base 64 decoding failed, assuming input is JWS")
        jws_raw = args.input

    # print(jws_raw)
    decoded_vc = decode_vc(jws_raw)
    payload_dict = json.loads(decoded_vc.payload)

    ##check that iss matches did in header
    assert payload_dict['iss'] == get_did_from_header(jws_raw)

    print(json.dumps(payload_dict, indent=4))

if __name__ == "__main__":
    main()
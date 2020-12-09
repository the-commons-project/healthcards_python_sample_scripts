from jwcrypto import jwk, jws, jwe
from jwcrypto.common import json_encode
import argparse
import json
from did.did_service import DIDService
import time
import secrets

def encode_vc(payload, did_long_identifier, private_signing_key, signing_key_name):

    ##create a jws token from the payload
    jwstoken = jws.JWS(json.dumps(payload).encode('utf-8'))

    ## sign the token, specifying the kid as concatenation of the did long identifier and the signing key name
    ## this will be used to resolve the signing key by the holder / verifier
    jwstoken.add_signature(
        private_signing_key, 
        None,
        json_encode({"alg": "ES256K", "typ": 'JWT', "kid": f'{did_long_identifier}#{signing_key_name}'})
    )

    ## return the jws as a string
    return jwstoken.serialize(compact=True)

def main():
    parser = argparse.ArgumentParser(description='Encodes a vc using the supplied DID config')
    parser.add_argument('config_file', help='Config file')
    parser.add_argument('input_file', help='Sample VC fixture file')
    parser.add_argument('output_file', help='Output file')

    args = parser.parse_args()
    with open(args.config_file, 'r', newline='') as config_file:
        config = json.load(config_file)

    did_long_identifier = config['did_long_identifier']

    ## jwk.JWK.from_json requires JSON string
    private_signing_key_json = json.dumps(config['signing_key'])
    private_signing_key = jwk.JWK.from_json(private_signing_key_json)
    signing_key_name = config['signing_key_name']

    with open(args.input_file, 'r') as input_file:
        payload = json.load(input_file)

        ##since we're using a static file to form the payload
        ## it needs to be modified a bit
        now = int(time.time())
        ##note that the iss prop needs to be set to the DID long identifier
        payload['iss'] = did_long_identifier

        payload['iat'] = now
        payload['nbf'] = now
        payload['nonce'] = secrets.token_urlsafe(16)

        ##if there  was a subject DID, we would add that here
        ##however, there isn't one, so delete it
        del payload['sub']

        vc_jws = encode_vc(payload, did_long_identifier, private_signing_key, signing_key_name)

    ## this is the general format for a FHIR backed vc file, this is subject to change
    with open(args.output_file, 'w') as outfile:
        output_dict = {
            'verifiableCredential': [vc_jws]
        }
        json.dump(output_dict, outfile)

if __name__ == "__main__":
    main()
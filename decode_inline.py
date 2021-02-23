import json
import argparse
import base64
import utils

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

    payload_dict = utils.decode_vc(jws_raw)

    print(json.dumps(payload_dict, indent=4))

if __name__ == "__main__":
    main()
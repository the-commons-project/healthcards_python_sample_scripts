import json
import argparse
import base64
import utils

def main():
    parser = argparse.ArgumentParser(description='Decodes a vc')
    parser.add_argument('input', help='Input resource')
    parser.add_argument('output_file', help='Output file')
    args = parser.parse_args()

    qr_img = utils.create_qr_code_from_numeric(args.input)
    with open(args.output_file, 'wb') as outfile:
        qr_img.save(outfile)

if __name__ == "__main__":
    main()



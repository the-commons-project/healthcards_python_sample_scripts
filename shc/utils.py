#!/usr/bin/env python
import zlib
import requests
from jose import jwk as jose_jwk, jws
import json
import qrcode

sample_payload = "eyJ6aXAiOiJERUYiLCJhbGciOiJFUzI1NiIsImtpZCI6IjNLZmRnLVh3UC03Z1h5eXd0VWZVQUR3QnVtRE9QS01ReC1pRUxMMTFXOXMifQ.3VRNT9swGP4rkbmmTZxQSnIaZZPWCRBSy3aYOLiOSbw5duSPlq7qf99rp4FOg952WW62Xz_v8-E3O8SNQSVqrO1MmSQUF2NKdGUS2HdMoxhxYlGJJwVO82lxnsZoTVG5Qx-okpY9w9n3l9ubzWa8ycdK10mW4suEalYxaTkRJllj9Bgju-2Yv_GVaf7EyUqw65ca6DUAmZZo2zAibNPTOaNqzStcnKzpFyO_OFnH29ZJ_otYrqQn9Upz4VY_GLVe31PDNbA0vqZE5-N0jAHU786crATzNZoZ5TRly6AKHQ4GlYgqIQDNI8QIGugtSAdkJ8SDFlAw3C9TKBgWbwDfA1W471GeLZM9J0ByAWUQWnPbuNWYqjZZaiJNRzRc-hyUJ5dpOrrIR_nIamcsWPLz7B7w1kQ4dq2q0AWjPbghSct6nqTlAiijKwk0tAkyar5mvjn6ohpJbEP85ozXtWDGKhnN53P06GFqJit4PyVqSfBkxSGFj8T6TriY4FGKR5nXTaoK5JrQslPGEnHgg7P8fAIFVLneO_SwAIb7ffymh_i0h_Pj0GMEfawzIaS2E8yyKrhBKZcHP3ZwVHFZB2JmayxrD2aD142Yhmfu30NieJXQ9XOgGphn6dQTjVF3CC7QeWKQh-d2nDsUKUqdDkfeniVve4gsWJR6WZ3mkNh2cdAGEbIYCUV7Me-B5x5cKHvn2lVI4kbZ6CwNH0T9jo3Zf2ljVvwTG6fv2piftvFm6DrMG7qaXUf3DdEtodvjqdghAV76icsKfJlFwN420S3hMlrY6O6T_4H9MTaTfJpdeBO59TNzSypuXsPyFd_mf03V3s_Vfv8b.6RJ6ZFwPRqsVdDXsEUaDhkRo0u3nKC1cSCgN7YyPM1tteqPziRNbEkMdvURrkZ3baECxqmDybQvpGKVmEorTNw"
sample_numeric_encoded_payload = "5676290952432060346029243740446031222959532654603460292540772804336028702864716745222809286133314564376531415906402203064504590856435503414245413640370636654171372412363803043756220467374075323239254334433260573601064137333912707426350769625364643945753638652852454535422237213876065244343160343853740855723835636810685712126967072534581208054242090543775073110024063411383336384168693404326438364025053330552640380527553266755975446326292974413411056375657045663941260836750066626744127412650663127253774252117654553004036442077072245263447552396237296363611221586172000544735026415257102476406874090854520923402064454566057720605333353934523368773871546530776725763450342565270512452950667144696836651240677707414450263141560604352333532003736845240800330361202740101109546920397733456645083937637609203027360726634458682836233328113628267258713820556229113823256320740622123930215842537423572004420710042656314532122903217620424036426535537233424468614545526029333777375400597640290855673469692837506528526454704235317710211074046236075568056803204261355358593854710965683963206060613074620371206276526908647361650966596729532435110866774371422326305965330806350309262568296071073576416838572162753826256111390939696044072526303708654339526630082969367063352624652758581035115720282541316556345038742028531057577664595060035950356103263224575274772852380524117676306959213045542735064574412725452105296452767569230552230407054459645772060333605629433612433458266759650955363961412506222210365642303659005505652370403040685523625756656041735607587042293709424506646233590554552026245328442240411032560021087508543027736505634128076253450922743327033912616606455705636141737439260957730567605771732564092369322610685243405706235524716655736168555859204110096054703057296325743307050338065932636944093409395007271232395239572967555621340812393377387667724370357625555064570306410670504157731153010937290945257435376870415523437024405223596237660372066530220454382258331044763532047171566835776037335324623255734037696245065352242275686423765336736726304164246669393374"
SMALLEST_B64_CHAR_CODE = ord('-')
SMART_HEALTH_CARD_PREFIX = 'shc:/'

# https://stackoverflow.com/a/1089787


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
    # needed to add `-zlib.MAX_WBITS` here due to
    # zlib.error: Error -3 while decompressing data: incorrect header check
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
                return key
                # TODO - the following line causes an exception to occur during verficiation
                # There's a fix on master for this, but for now, it does not work
                #
                #   File "/usr/local/lib/python3.7/site-packages/jose/jws.py", line 233, in _get_keys
                #       if 'keys' in key:
                # TypeError: argument of type 'CryptographyECKey' is not iterable
                # return jwk.construct(key, algorithm)

        raise Exception(f'Key with kid = {kid} not found')

    return resolve


def resolve_key_from_file(jwks_filename):
    def resolve(iss, kid, algorithm):
        with open(jwks_filename, 'r', newline='') as jwks_file:
            jwks = json.load(jwks_file)

        for key in jwks['keys']:
            if kid == key.get('kid'):
                return key
                # TODO - the following line causes an exception to occur during verficiation
                # There's a fix on master for this, but for now, it does not work
                #
                #   File "/usr/local/lib/python3.7/site-packages/jose/jws.py", line 233, in _get_keys
                #       if 'keys' in key:
                # TypeError: argument of type 'CryptographyECKey' is not iterable
                # return jwk.construct(key, algorithm)

        raise Exception(f'Key with kid = {kid} not found')

    return resolve


def load_private_key_from_file(jwks_filename, use, algorithm):
    with open(jwks_filename, 'r', newline='') as jwks_file:
        jwks = json.load(jwks_file)

    for key in jwks['keys']:
        if algorithm == key.get('alg') and use == key.get('use'):
            return (key.get('kid'), key)
            # TODO - the following line causes an exception to occur during verficiation
            # There's a fix on master for this, but for now, it does not work
            #
            #   File "/usr/local/lib/python3.7/site-packages/jose/jws.py", line 233, in _get_keys
            #       if 'keys' in key:
            # TypeError: argument of type 'CryptographyECKey' is not iterable
            # return jwk.construct(key, algorithm)
            # return (key.get('kid'), jose_jwk.construct(key, algorithm))

    raise Exception(f'Key with use = {use} algorithm = {algorithm} not found')


def _decode_vc(jws_raw, key_resolver):
    # before we can verify the vc, we first need to resolve the key
    # the key ID is stored in the header
    # Per the health cards IG,
    ## "Issuers SHALL publish keys as JSON Web Key Sets (see RFC7517), available at <<iss value from Signed JWT>> + .well-known/jwks.json"
    # therefore, we need decode the claims to get the iss value in order to resolve the key
    # The claims are compressed via Deflate, so decompress the data
    # then, extract the iss claim to get access to the base URL, use that to resolve key with id = kid
    # then, verify the jws
    unverified_headers = jws.get_unverified_headers(jws_raw)

    # we expect data to be zipped, so deflate the data
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


def encode_vc(payload, private_signing_key, kid):

    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    compressed_payload = deflate(payload_bytes)

    headers = {"kid": kid, 'zip': 'DEF'}
    return jws.sign(compressed_payload, private_signing_key, headers=headers, algorithm='ES256')


def encode_char_to_numeric(ch):
    numeric_value = ord(ch) - SMALLEST_B64_CHAR_CODE
    return '%02d' % (numeric_value)


def encode_to_numeric(payload):
    return ''.join([encode_char_to_numeric(ch) for ch in payload])


def create_qr_code(numeric_encoded_payload):
    qr = qrcode.QRCode()
    qr.add_data(SMART_HEALTH_CARD_PREFIX)
    qr.add_data(numeric_encoded_payload)
    return qr.make_image(fill_color="black", back_color="white")

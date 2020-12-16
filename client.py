import sys
import os
import requests
import base64
import struct
import fido2.cbor as cbor

from authenticator import Authenticator


class Client:
    rp_url = None,
    username = None,
    pin = None
    authenticator = None

    def __init__(self, rp_url: str, username: str, pin: str):
        self.rp_url = rp_url
        self.username = username
        self.pin = pin
        self.authenticator = Authenticator(rp_url).get_conn()

    def register(self):
        # Get server challenge
        url = self.rp_url + '/makeCredential/' + self.username
        resp = requests.get(url)
        registration_cookie = resp.cookies.get('webauthn-session')
        cred_creation_options = resp.json().get('publicKey')
        cred_creation_options['challenge'] = base64.urlsafe_b64decode(cred_creation_options['challenge'])
        cred_creation_options['user']['id'] = base64.urlsafe_b64decode(cred_creation_options['user']['id'])

        cred_creation_options['extensions'] = {'hmacCreateSecret': True}

        # Create credential on the authenticator
        print("\nTouch your authenticator device now...\n")

        resp = self.authenticator.make_credential(
            cred_creation_options, pin=self.pin
        )

        attestation_object = resp.attestation_object
        client_data = resp.client_data

        # Register credential at the RP
        cred_id = str(base64.urlsafe_b64encode(attestation_object.auth_data.credential_data.credential_id), 'ascii').rstrip('=')
        attestation_object_bin = cbor.encode(dict((k.string_key, v) for k, v in attestation_object.data.items()))
        payload = {
            'id': cred_id,
            'rawId': cred_id,
            'response': {
                'attestationObject': str(base64.urlsafe_b64encode(attestation_object_bin), 'ascii').rstrip('='),
                'clientDataJSON': client_data.b64
            },
            'type': 'public-key'
        }
        register_credential_url = self.rp_url + '/makeCredential'
        resp = requests.post(register_credential_url, json=payload, cookies={'webauthn-session': registration_cookie})

        if not resp.ok:
            print('Registration error.')
            sys.exit(1)

        print("New credential created!")
        print("CLIENT DATA:", client_data)
        print("ATTESTATION OBJECT:", attestation_object)

    def authorize(self, tx, tx_attack):
        # Get options from RP
        get_assertion_options_url = self.rp_url + '/assertion/' + self.username
        resp = requests.get(get_assertion_options_url, params={'txAuthExtension': tx})
        assertion_cookie = resp.cookies.get('webauthn-session')
        assertion_options = resp.json().get('publicKey')
        assertion_options['challenge'] = base64.b64decode(assertion_options['challenge'])

        salt = os.urandom(32)
        assertion_options['extensions']['hmacGetSecret'] = {'salt1': salt}

        if tx_attack:
            assertion_options['extensions']['txAuthSimple'] = tx_attack

        for k, v in enumerate(assertion_options['allowCredentials']):
            assertion_options['allowCredentials'][k]['id'] = base64.urlsafe_b64decode(v['id'])

        # Generate assertion
        print("\nTouch your authenticator device now...\n")

        resp = self.authenticator.get_assertion(assertion_options, pin=self.pin)
        assertion = resp.get_response(0)  # just take the first assertion - it's only a poc

        cred_id = str(base64.urlsafe_b64encode(assertion['credentialId']), 'ascii').rstrip('=')

        ad = assertion['authenticatorData']
        auth_data = ad.rp_id_hash \
            + struct.pack(">BI", ad.flags, ad.counter) \
            + (cbor.encode(ad.extensions) if ad.extensions is not None else b"")

        signature = assertion['signature']

        payload = {
            'id': cred_id,
            'rawId': cred_id,
            'response': {
                'authenticatorData': str(base64.urlsafe_b64encode(auth_data), 'ascii').rstrip('='),
                'clientDataJSON': assertion['clientData'].b64,
                'signature': str(base64.urlsafe_b64encode(signature), 'ascii').rstrip('='),
                'userHandle': ''
            },
            'type': 'public-key'
        }
        register_credential_url = self.rp_url + '/assertion'
        resp = requests.post(register_credential_url, json=payload, cookies={'webauthn-session': assertion_cookie})

        if not resp.ok:
            print('Authorization error.')
            sys.exit(1)

        print("Transaction authorized!")
        print("CLIENT DATA:", assertion['clientData'])
        print("ASSERTION DATA:", assertion)

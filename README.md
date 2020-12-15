# FIDO2 client with support for txAuthSimple extension

As the two major browsers for GNU/Linux currently don't support the [WebAuthn txAuthSimple extension](https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#sctn-simple-txauth-extension), this client was created. It's taylored to work in combination with the [patched WebAuthn server](https://github.com/cyrillbolliger/webauthn.io) of [Duo Labs](https://duo.com/labs/).

Use for testing purposes only.

## Installing the Client

1. `python3 -m venv ./venv`
1. `source venv/bin/activate`
1. `pip3 install -r requirements.txt`


## Register your Authenticator

1. Plug-in your Authenticator
1. Run `./main.py --rp_url=<url_of_the_relying_party> register <username>`


## Authorize Transaction

`./main.py --rp_url=<url_of_the_relying_party> --tx="<string_of_txAuthSimple_extension>" authorize <username>`

## Test Round-Trip-Integrity

`./main.py --rp_url=<url_of_the_relying_party> --tx="<string_of_txAuthSimple_extension>" --tx_attack="<modified_string_of_simpleTxAuth_extension>" authorize <username>`

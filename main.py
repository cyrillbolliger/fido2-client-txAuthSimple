#!/usr/bin/env python3

import argparse
from client import Client

# defaults
rp_url = "http://localhost:9005"

# start reading cli arguments
parser = argparse.ArgumentParser()

parser.add_argument("action",
                    help="'register' an authenticator/user or 'authorize' a transaction",
                    choices=['register', 'authorize'])
parser.add_argument("user",
                    help="username")

parser.add_argument("--rp_url", help="URL of the relying party", default=rp_url)
parser.add_argument("--pin", help="authenticator pin", default="")
parser.add_argument("--tx", help="transaction details: string that should be shown to the user")
parser.add_argument("--tx_attack",
                    help="simulate evil client and overwrite the transaction details with the given string")

args = parser.parse_args()

# launch program
client = Client(str(args.rp_url), str(args.user), str(args.pin))

if 'authorize' == args.action:
    client.authorize(str(args.tx), str(args.tx_attack))

elif 'register' == args.action:
    client.register()

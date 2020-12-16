from yubico.fido2.hid import CtapHidDevice
from yubico.fido2.client import Fido2Client
import sys


def get_dev():
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is not None:
        print("Use USB HID channel.")
    else:
        print("No FIDO device found")
        sys.exit(1)

    return dev


def verify_rp_id(rp_id, origin):
    return True


class Authenticator:
    __rp_url = None
    __dev = None

    def __init__(self, rp_url):
        self.__rp_url = rp_url
        self.__dev = get_dev()

    def get_conn(self):
        return Fido2Client(self.__dev, self.__rp_url, verify_rp_id)

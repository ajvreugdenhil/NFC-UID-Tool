from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.ATR import ATR
from smartcard.CardType import AnyCardType
from smartcard.pcsc import PCSCExceptions
import sys
import logging

logging.basicConfig(
    format='%(asctime)s\t%(levelname)s\t%(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

r = None
try:
	r = readers()
except PCSCExceptions.EstablishContextException:
	logger.critical("Could not contact pcscd")
	exit(1)

if len(r) < 1:
	logger.critical("error: No readers available!")
	exit(1)

logger.info("Available readers: " + str(r))
# TODO: let user pick reader
reader = r[0]
logger.info("Using: " + str(reader))
connection = reader.createConnection()
connection.connect()


# ACR magic numbers
ACR_MUTE = [0xFF, 0x00, 0x52, 0x00, 0x00]
ACR_UNMUTE = [0xFF, 0x00, 0x52, 0xFF, 0x00]
ACR_GETUID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
ACR_FIRMVER = [0xFF, 0x00, 0x48, 0x00, 0x00]
# TODO: check where getuid and firmver belong

# General magic numbers
data_write_command = [0xff, 0xd6, 0x00] # Append blocknr, data len, data

# Desfire specific magic numbers
blocknr = 0x0
desfire_write_uid_command_size = 0x0e
desfire_write_uid_command = [0xff, 0x00, 0x00, blocknr, desfire_write_uid_command_size, 0xd4, 0x42, 0x90, 0xf0, 0xcc, 0xcc, 0x10]
desfire_backdoor_command_one = [0xff, 0xca, 0x00, 0x00, 0x00]
desfire_backdoor_command_two = [0xff, 0x00, 0x00, 0x00, 0x04, 0xd4, 0x4a, 0x01, 0x00]

# Classic specific magic numbers
#TODO


def _write(data):
    data_as_hex = ' '.join(format(x, '02x') for x in data)
    logger.debug("Writing data: " + str(data_as_hex))
    returndata, sw1, sw2=connection.transmit(data)
    logger.info("Got status words: %02X %02X" % (sw1, sw2))
    if ((sw1, sw2) == (0x90, 0x0)):
        return (True, returndata)
    elif (sw1, sw2) == (0x63, 0x0):
        logger.error("Got bad response")
        return (False, None)

def get_uid():
    status, retdata = _write(ACR_GETUID)
    return retdata

def write_data_block(blocknr, userdata):
    userdata_values = bytes.fromhex(userdata)
    # Note, mfclassic only allows writing of 16 bytes at a time (that's one block)
    assert len(userdata_values) == 16
    write_command = data_write_command + [blocknr, len(userdata_values)]
    for b in userdata_values:
        write_command.append(b)
    _write(write_command)

def write_uid_desfire(newuid: str):
    uid_values = bytes.fromhex(newuid)
    assert len(uid_values) == 7
    logger.info("Setting uid to " + str(uid_values))
    write_command = desfire_write_uid_command  + [i for i in uid_values]
    _write(desfire_backdoor_command_one)
    _write(desfire_backdoor_command_two)
    _write(write_command)


def main():
    logger.error("Be careful! Somewhere along the line I borked my only 7B card. This current code is not known-good")
    '''
    write_uid_desfire("aabbccddeeff11")
    uid = get_uid()
    print("UID: " + ' '.join('{:02x}'.format(x) for x in uid))
    '''


if __name__ == "__main__":
    main()
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

def write_uid_mfclassic(uid):
    print("We recommend you use nfc-mfsetuid for now")
    raise NotImplemented
    uid = sys.argv[2]
    uid_values = bytes.fromhex(uid)
    assert len(uid_values) == 4
    
    original_blockzero = [0xCA, 0xFE, 0xBA, 0xBE, 0x30, 0x08, 0x04, 0x00, 0x46, 0x59, 0x25, 0x58, 0x49, 0x10, 0x23, 0x02]
    example_write_to_zero = [0x01,  0xff,  0xff,  0xff,  0xfe,  0x08, 0x04,  0x00,  0x46,  0x59,  0x25,  0x58,  0x49,  0x10,  0x23,  0x02,  0x39,  0x08]

    blocknr = 0x0
    write_command = [0xFF, 0xD6, 0x00, blocknr, 0x7]
    for b in original_blockzero:
        write_command.append(b)
    
    #write_command = [0xff, 0x00, 0x00, 0x00, 0x14, 0xd4, 0x42, 0x41, 0x41, 0x41, 0x41, 0x00, 0x08, 0x04, 0x00, 0x46, 0x59, 0x25, 0x58, 0x49, 0x10, 0x23, 0x02, 0xe9, 0x60]
    backdoor_command_zero = [0xff, 0x00, 0x00, 0x00, 0x06, 0xd4, 0x42, 0x50, 0x00, 0x57, 0x00]
    backdoor_command_one = [0xff, 0x00, 0x00, 0x00, 0x05, 0xd4, 0x08, 0x63, 0x3d, 0x00]
    #backdoor_command_one = [0xff, 0x00, 0x00, 0x00, 0x03, 0xd4, 0x42, 0x40]
    backdoor_command_two = [0xff, 0x00, 0x00, 0x00, 0x03, 0xd4, 0x42, 0x43]
    backdoor_command_three = [0xff, 0x00, 0x00, 0x00, 0x06, 0xd4, 0x42, 0xa0, 0x00, 0x5f, 0xb1]
    _write(backdoor_command_one)
    _write(backdoor_command_two)
    _write(backdoor_command_three)
    _write([0xff, 0x00, 0x00, 0x00, 0x14, 0xd4, 0x42] + example_write_to_zero)
    '''
    behavior of nfc-mfsetuid:
                d5 43 0041414141009000 # answer, this is my uid

    ff000000 0b  d4 42 93704141414100e21a # select?
    ff000000 06  d4 42 500057cd
    ff000000 04  d4 06 633d
    ff000000 05  d4 08 633d07
    ff000000 03  d4 42 40
    ff000000 04  d4 06 633c
    ff000000 04  d4 06 633d
    ff000000 05  d4 08 633d00
    ff000000 03  d4 42 43
    ff000000 06  d4 42 a0005fb1
    ff000000 14  d4 42 cafebabe300804004659255849102302a064
    ff000000 02  d4 02
    ff000000 03  d4 52 00
    ff000000 04  d4 32 0100
    '''
    '''
    00  00  00  00  00  08  04  00  46  59  25  58  49  10  23  02  1a  f0
    00  00  00  01  01  08  04  00  46  59  25  58  49  10  23  02  e2  70
    00  00  00  02  02  08  04  00  46  59  25  58  49  10  23  02  fb  f9
    00  00  00  03  03  08  04  00  46  59  25  58  49  10  23  02  03  79
    00  00  00  04  04  08  04  00  46  59  25  58  49  10  23  02  d8  e3
    00  00  00  ff  ff  08  04  00  46  59  25  58  49  10  23  02  0e  c0
    00  00  01  00  01  08  04  00  46  59  25  58  49  10  23  02  a5  0b
    00  00  01  ff  fe  08  04  00  46  59  25  58  49  10  23  02  b1  3b
    00  00  ff  ff  00  08  04  00  46  59  25  58  49  10  23  02  8f  a6 
    00  ff  ff  ff  ff  08  04  00  46  59  25  58  49  10  23  02  7c  03
    01  ff  ff  ff  fe  08  04  00  46  59  25  58  49  10  23  02  39  08
    |------------|
    uid
                    |
                    xor uid vals
    '''



def main():
    logger.error("Be careful! Somewhere along the line I borked my only 7B card. This current code is not known-good")
    
    '''
    write_uid_desfire("aabbccddeeff11")
    uid = get_uid()
    print("UID: " + ' '.join('{:02x}'.format(x) for x in uid))
    '''

    '''
    uid[0] += 1
    write_uid_desfire(''.join('{:02x}'.format(x) for x in uid))

    uid = get_uid()
    logger.info("UID: " + ' '.join('{:02x}'.format(x) for x in uid))
    '''



if __name__ == "__main__":
    main()
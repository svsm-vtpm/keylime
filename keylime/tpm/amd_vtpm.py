from keylime import keylime_logging
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils, ec
import requests
import struct
import json

logger = keylime_logging.init_logging('vtpm')

def measurement_allowed(measurement, allowed_list_json):
    for i in allowed_list_json:
        if i['measure'] == measurement:
            return True

    return False

def get_vcek(EKcert_surrogate):
    tcb=struct.unpack('<BB4xBB', EKcert_surrogate[0x180:0x188])
    chipID=struct.unpack('<64s', EKcert_surrogate[0x1a0:0x1E0])[0].hex()
    url = ("https://kdsintf.amd.com/vcek/v1/Milan/" + chipID +
           "?blSPL=%02d"%tcb[0] + "&teeSPL=%02d"%tcb[1] +
           "&snpSPL=%02d"%tcb[2] + "&ucodeSPL=%02d"%tcb[3])

    response = requests.get(url)

    if (response.status_code < 200 or response.status_code > 299):
        logger.error("Could not download vcek")
        return None

    return response.content

def is_amd_vtpm_ek_valid(EKpub, EKcert_surrogate):
    ekpub_sha512=struct.unpack('<64s', EKcert_surrogate[0x50:0x90])[0]
    hasher = hashes.Hash(hashes.SHA512())
    hasher.update(EKpub)
    digest = hasher.finalize()
    return (digest == ekpub_sha512)

# TODO: is this good enough?
def is_amd_vtpm(EKcert_surrogate):
    version = struct.unpack('<I', EKcert_surrogate[0x0:0x4])[0]
    vmpl=struct.unpack('<I', EKcert_surrogate[0x30:0x34])[0]
    return (vmpl == 0) and (version == 2) and (len(EKcert_surrogate) == 1184)

def verify_ekcert_surrogate(EKcert_surrogate, mb_refstate: dict):
    vmpl=struct.unpack('<I', EKcert_surrogate[0x30:0x34])[0]
    if (vmpl > 0):
        logger.error("Using an attestation report from VMPL %d"%vmpl)
        return False

    # load SEV launch measurement, compare with measured boot refstate (if there is one)
    alm="0x" + struct.unpack('<48s', EKcert_surrogate[0x90:0xC0])[0].hex()
    logger.info("actual launch measurement=%s"%(alm))
    if not (mb_refstate and 'launch_measurements' in mb_refstate):
        logger.info("SEV launch measurement ignored because mb_refstate does not have launch measurements")
    elif alm in mb_refstate['launch_measurements']:
        logger.info("SEV launch measurement found in measured boot refstate")
    else:
        logger.error("SEV launch measurement does not match any provided in the measured boot refstate")
        return False
    
    sigRS=struct.unpack('<72s72s368x', EKcert_surrogate[0x2A0:0x4A0])
    R=int.from_bytes(sigRS[0], 'little')
    S=int.from_bytes(sigRS[1], 'little')
    signature = utils.encode_dss_signature(R,S)

    hasher = hashes.Hash(hashes.SHA384())
    hasher.update(EKcert_surrogate[0:0x2A0])
    digest = hasher.finalize()

    vcek = get_vcek(EKcert_surrogate)
    cert = x509.load_der_x509_certificate(vcek)
    public_key = cert.public_key()

    try:
        public_key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA384())))
    except Exception as e:
        logger.error("Failed to verify signature, %s"%(str(e)))
        return False

    logger.info("Successfully verified amd vTPM attestation report")
    return True

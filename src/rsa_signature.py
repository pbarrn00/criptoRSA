import hashlib
from rsa import rsa_decrypt, rsa_encrypt

def sha256(by: bytes) -> bytes:
    '''
    Computes the SHA-256 hash of a message

    Parameters
    ----------
    by : bytes
        Message to be hashed

    Returns
    -------
    bytes
        SHA-256 hash of the message

    '''
    return hashlib.sha256(by).digest()

def rsa_sign(by: bytes, n: int, d: int) -> bytes:
    '''
    Sign a message using RSA

    Parameters
    ----------
    by : bytes
        Message to sign
    n: int
        Public modulus of receiver
    d : int
        Private exponent of receiver

    Returns
    -------
    bytes
        The signature

    '''
    return rsa_encrypt(by, n, d)

def rsa_verify(by: bytes, n: int, e: int, signature: bytes) -> bool:
    '''
    Verify a message using RSA

    Parameters
    ----------
    by : bytes
        Message to verify
    n: int
        Public modulus of receiver
    e : int
        Public exponent of receiver
    signature : bytes
        Signature to verify

    Returns
    -------
    bool
        True if the signature is valid, False otherwise

    '''
    print("\nDecrypted: ",rsa_decrypt(signature, n, e))
    return rsa_decrypt(signature, n, e) == by

def main():

    # =========================================================================== #
    # ================================= RSA KEYS ================================ #
    # =========================================================================== #
    #(n, e), d = rsa_keygen(1024)


    # My keys
    barrio_n = 137240983915996962747909454484640658542329656056449401370891990025072346702917945425463397482231359266614646060111542095646286224283115300273103159970060217155569265862077406621057638854015677632691187303616523985260804276248741993354084069774341050814080965415297141189501657346954323426277281084454908433239
    barrio_e = 65537
    barrio_d = 6883304303399331927802285379114299474016777994988314727651890858788360828425031457245497772618436576428007714719725328721017788718107328562456171121985868388459121123365468232335586419704900978200225152417136113477503589035247290364170055315820304822024943118646069037558371444580320459226977033054563966129

    print("")
    print("n_barrio:", barrio_n)
    print("e_barrio:", barrio_e)
    print("d_barrio:", barrio_d)
    print("")
    print("===========================================================")

    # de la Hera's keys
    delahera_n = 110477620934049393733275265425319715013384221791352610600040838995728481009667690503849981506344012764292009379787793009565139234703193116888335807677802785350021945337615918588620239492464432226348696954426754149567553978837124726589912929545140618195782211815916207778575351484388869984100139595053059887809
    delahera_e = 65537

    
    print("")
    print("n_dela:", delahera_n)
    print("e_dela:", delahera_e)
    print("")
    print("===========================================================")

    # =========================================================================== #
    # ================================ RSA SGIN ================================= #
    # =========================================================================== #

    message_barrio = b"Hola buenas tardes"
    print("Mensaje de Barrio: {}".format(message_barrio))
    print("")

    hashed_message_barrio = sha256(message_barrio)
    print("Hash del mensaje de Barrio: {}".format(hashed_message_barrio))
    print("")

    message_encrypted_barrio = rsa_encrypt(message_barrio, delahera_n, delahera_e)
    print("Mensaje encriptado de Barrio: {}".format(message_encrypted_barrio))
    print("")

    signature_barrio = rsa_sign(hashed_message_barrio, barrio_n, barrio_d)
    print("Firma del mensaje de Barrio: {}".format(signature_barrio))
    print("")
    print("===========================================================")

    # =========================================================================== #
    # ============================ RSA VERIFY =============================== #
    # =========================================================================== #
    
    encrypted_message_delahera = b'\x08\x80\xa6\xa2>\x7fh\xa15#\xba\x03T<G*\xed\x18\xf9\xe4\xf1\xe0\xa3hM\xcd}\x17\xfb\xa6\x8e\x92B\x9bmQX\xa2\xfe5\xdd/\xe6\x9e\xf7\xe4\x97\xfb\xb2\xd4\xeeai\xac\xe9d\xd0\xc4\x10\x83\xec\xbd\x856O\xb5\x9d@\xbf\x06\xfb\x1b\x0b\xc9\xf8\x9c\x18\x10&\xe8\xde\xa40\x1a\xe6\xe9\x98>\x99\xcd\x03\xf8\x96\x84\xd0\xab\x90\xa4\xc8v\xc4\xdb\x85\xaa\x90\x06n\x90\xa7u\xc0`\'\xe5\x15w\xc6\x0b`\x03\xa3p\xce\xd1cQ\xe2\xfaH,\x07<j\xae\x00j\xba\xa2,\xdc\x8db-[\xc9\xaa\xbd\x14\x97\x9a\xe42\x8cP\xca\xe2Y!\xc3]z\xfe*s\xdb\x95\xec\xeb\xed\x935D\x8a\xdd\xa9\xf2\xa1\xc6\xd8c\xfe\xd7\xb2\x98&5`\xc7J~\xb1zVa\x91%z\xb2\xe76h@\xe7\x07|Q\x93K"\x83\x93u\x8b\x14\x87\xb6C\x90d\x9bH\x832+=\x02\xfa\xda\xaf\xf6M#\x0eg\x9b\xa5U\xc0\x16\x11\x06M\x11\xd39\xdc\x13\xa9,\xd8Q\xf0\xc0\x9eh\x8c'
    print("Mensaje de de la Hera: {}".format(encrypted_message_delahera))
    print("")

    signature_delahera = b"d\x97\x8a\x8d'\xa2\xbe\x93\x95\x10\xe7Z\xf6%\xfc\xaa\x92{\x1b\xc0\x1a\xb4\xad_\xa5\x87t/Y\x99\x9b=y\x0f\xf00\xe7\xe4\xb2\xdb\xdb2\xc3\xd4\x03\x98N\xaa\xcb\x1f\x96\xf9\xe0 }\x16{^!j\xf9F\xc1\x05\xc5\xfc9\xfd$7S\xebz\xe4x\xc7@&\xdb\x0c\x0c\x9f\xf2\xe6h\xe2\xc2\xed\xf3[\x14\x11(q\xbev]LG\xcf]\xbe\xcc\x04\xa2\xe7\xf0\xd1Z8u#\xeen\xa9\x83\xf8\x1e\x1b\xf3(\xa7$\xdc\x9e\xec\xf3\xf1\x8bT\x07\tE\xfaB\xce\xf9\xa0\xe6\xfd\xc0\xbbw\xd5Jn_\x8e=^\xa7fV]\x93*\x19\x01\xd14u\x08p\x0cf\xf8q\xe8K[\x1c\xaa\xc7\x0f`,3\x04Mo\x90\x96\xb8\x0f\x7fW@l\x8d\xa2\xc6\xa5R/u-\xce\xf2\x88a\xcard>\xfd\xadk\xd9S\xd3vS0ha\x8e\xdd\xf6\xe4\x16\xa8JY\x9a\xc9\xbf2N/;\xb0\x7f;u\xe6;R?`R\xf7\xdcO\xb3\xec\xe1\xa0}S\xc6\xa4\x15g2\x8d\xd6"

    decrypted_message_delahera = rsa_decrypt(encrypted_message_delahera, barrio_n, barrio_d)
    print("Mensaje desencriptado de de la Hera: {}".format(decrypted_message_delahera))
    print("")

    print("Firma del mensaje de de la Hera: {}".format(signature_delahera))
    print("")

    print("===========================================================")
    print("Verifying signature...")
    print("Signature valid: {}".format(rsa_verify(sha256(decrypted_message_delahera), delahera_n, delahera_e, signature_delahera)))

    #print("\nMensaje de De La Hera: ", decrypted_delahera.decode("utf-16"))

if __name__ == '__main__':
    main()
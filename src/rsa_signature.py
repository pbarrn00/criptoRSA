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
    barrio_n = 123355434931394847582156130589346765195239858952662033973669968405220821412574991703109181733654539246644904338901352138362092833002288793510559272266372536290821137928735835297624136288059785492583366524665701693180230633068234558088660840330170848973749265206460835623134857700697302798342737456620402409063
    barrio_e = 65537
    barrio_d = 21547721425982394908532941437460392876620930242307016874903852759555182012163487877339425248132767219976362434529238129300536166626641471353722058515120199875152893394899024737510268376182081351858353560598824321590099317711440609093139218884302631847656040275633159758135761177701388215160028530955592998913

    print("")
    print("n_barrio:", barrio_n)
    print("e_barrio:", barrio_e)
    print("d_barrio:", barrio_d)
    print("")
    print("===========================================================")

    # de la Hera's keys
    delahera_n = 102177145502170449647535015823292055188749752771393005649892105979200067597554948297407387457859709511918845152650987194391543702482122356296402530264892095093397819813676815413255338683528599712279533202539803336778869663204648825602128229440285623432111299318482515655843275628377999479423128550587755875503
    delahera_e = 65537
    
    print("")
    print("n_dela:", delahera_n)
    print("e_dela:", delahera_e)
    print("")
    print("===========================================================")

    # =========================================================================== #
    # ================================ RSA SGIN ================================= #
    # =========================================================================== #

    message_barrio = b"hola buenas tardes"
    print("Mensaje de Barrio: {}".format(message_barrio))
    print("")

    hashed_message_barrio = sha256(message_barrio)
    print("Hash del mensaje de Barrio: {}".format(hashed_message_barrio))
    print("")

    signature_barrio = rsa_sign(hashed_message_barrio, delahera_n, barrio_d)
    print("Firma del mensaje de Barrio: {}".format(signature_barrio))
    print("")
    print("===========================================================")

    # =========================================================================== #
    # ============================ RSA VERIFY =============================== #
    # =========================================================================== #
    
    hashed_message_delahera = b'\xa5\x91\xa6\xd4\x0b\xf4 @J\x01\x173\xcf\xb7\xb1\x90\xd6,e\xbf\x0b\xcd\xa3+W\xb2w\xd9\xad\x9f\x14n'
    print("Hash del mensaje de de la Hera: {}".format(hashed_message_delahera))
    print("")

    signature_delahera = b"\x0f7+\x13U\xfb\xa3\xda\x1a\x00\x8bFH\xef\x19\x89\xb7\x0c\x00\xd5N\x11Tu\x16\x9e\xf1\x1b`FO@\xf8\x96\x17\xfa\xb5\xd8\xc6'n\xbdf$\x18\xb3\xd6\xe00\x05\x89\x1f'-\xe8\xee\x8b\xcd\xb9\x97\x96L(\x1aA?\x01;\x9at3\xf3\x13\x98\x0eYa\x10LHS\x899L\x98\x15\x18\x9fq\xbd\xfe\x8eh\x16N\xb1\xe1\x93\xa1z\xee\x82F\x19\xd2\xfe\xd0C/[\xb8IC\x85(P\x9b\xc5$\x9d\x11s\x18\x0e\xa8PE\xdc\x90\x97\\\xc4L/c[\x1a\xd7\xcc\xadU.\x11`\xfd\x9b\xb1\x8arZH\x9e\xc8\xfe\x14\x0f\xa9\x82k\x1f\x06\xea\xee\xb8\x9f\xe4\xc8\xb7+\xad\x83\x1a\xd4\xec\x07\x04\x02\x16\x19\x05\xf4\x8fWE\x1a>jB\xc9U`\x90\xc4\xbc\x9dc\xf8\xeaD\xa9\xa8\x1b\x96\xf3Ux6\xad\xb8/\x88\xae\x97\x0e\xd5\x15\xb1K\x1b^b~\x06\xc3\xe1\xc6\xc2]P\xb8\xae\xcf\x91(\x8f\xc9\xa9\xd2\xeb\x8fK\x17V\xb12\x08\x9f\x01\x81\x1c\xe0F\xa6\x1aB\xff"

    print("Firma del mensaje de de la Hera: {}".format(signature_delahera))
    print("")

    print("===========================================================")
    print("Verifying signature...")
    print("Signature valid: {}".format(rsa_verify(hashed_message_delahera, delahera_n, delahera_e, signature_delahera)))

    #print("\nMensaje de De La Hera: ", decrypted_delahera.decode("utf-16"))

if __name__ == '__main__':
    main()
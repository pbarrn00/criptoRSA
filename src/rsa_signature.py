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

    signature_barrio = rsa_sign(hashed_message_barrio, barrio_n, barrio_d)
    print("Firma del mensaje de Barrio: {}".format(signature_barrio))
    print("")
    print("===========================================================")

    # =========================================================================== #
    # ============================ RSA VERIFY =============================== #
    # =========================================================================== #
    
    hashed_message_delahera = b'\xa5\x91\xa6\xd4\x0b\xf4 @J\x01\x173\xcf\xb7\xb1\x90\xd6,e\xbf\x0b\xcd\xa3+W\xb2w\xd9\xad\x9f\x14n'
    print("Hash del mensaje de de la Hera: {}".format(hashed_message_delahera))
    print("")

    signature_delahera = b'3\xe4\x90\xfd\xb6\x00>\xf2\xf1\x13\x82C\xbeC\x9c\xd6+K^\xf9\x0b\xbeGwU\xe4\xe1\x17sm\xa3\xfe\xe3eNq\x15\x0c\xda0\xef\xd8\x99\x1c:L\x19\xb2\x03\x93h\xe6p\xa1u\xde\x07\xa7$}\xf0r\x8e\x8dn}\xcf4\xfe.\x19\x90E$\x7fv3og\x0b\x15V\xb4\xff\x92I>\xc1K\x80\x1b\xdd\xbd\x9ay(\xf1\x1b\x89;;\xd5\xba\xf8\xe9\xae\x06\xe27ZA\xff\x96\n\x1b\x00\x81\x0cJ\xd06\x99@F\x8d\xd9\xeb\x9c\x8cVU\x94P4\x95\xd2"\xa80\x15\xa1{I\xcb>\x0c.J\xc5N\x08F\xe9\xe5$\xe6\xb1Lo9\xf5\x11\xf3\xbaU\x8e;y]\x8e\xbf\x0e\xef\x81\xd2\xd7\x16\xca\t\xef\xa0\xb7\xdb\'\x90%^\xb2\x14\xd9\xc2-\x88fn\xfbY\xad9\x18;@4\x85qp\xb9\x0fW\xe1\xccx\xc2^V*\xf6\t\xa5\xcf\xd5I\x12\xef\xe7\xf0\xc9\x9a\x89\x02\xc7:\xbd\x8e\xc4 R\xda\xedq\xba\xb3)\xadR\xb1\xdf\xf8\x12\x15\xb0\xff\x82\x06\x93P'


    print("Firma del mensaje de de la Hera: {}".format(signature_delahera))
    print("")

    print("===========================================================")
    print("Verifying signature...")
    print("Signature valid: {}".format(rsa_verify(hashed_message_delahera, delahera_n, delahera_e, signature_delahera)))

    #print("\nMensaje de De La Hera: ", decrypted_delahera.decode("utf-16"))

if __name__ == '__main__':
    main()
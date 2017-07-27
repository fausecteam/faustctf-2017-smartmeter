from ctypes import CDLL, c_voidp, c_int, c_long, Structure, POINTER, c_char, c_uint, c_char_p, c_size_t, cast, byref, addressof
import os.path

class crypto_ex_data_st(Structure):
    _fields_ = [
        ("sk", c_voidp),
        ("dummy", c_int),
    ]

class dh_st(Structure):
    _fields_ = [
        ("pad", c_int),
        ("version", c_int),
        ("p", c_voidp),
        ("g", c_voidp),
        ("length", c_long),
        ("pub_key", c_voidp),
        ("priv_key", c_voidp),
        ("flags", c_int),
        ("method_mont_p", c_voidp),
        ("q", c_voidp),
        ("j", c_voidp),
        ("seed", c_voidp),
        ("seedlen", c_int),
        ("counter", c_voidp),
        ("references", c_int),
        ("ex_data", POINTER(crypto_ex_data_st)),
        ("meth", c_voidp),
        ("engine", c_voidp),
    ]

class evp_pkey_st(Structure):
    _fields_ = [
        ("type", c_int),
        ("save_type", c_int),
        ("references", c_int),
        ("ameth", c_voidp),
        ("engine", c_voidp),
        ("dh", POINTER(dh_st)), # actually a union where we only care about this field
        ("save_parameters", c_int),
        ("attributes", c_voidp),
    ]


class Schnorr:
    schnorr = CDLL(os.path.join(os.path.dirname(__file__), ".", "libschnorr.so"))
    crypto = CDLL("libcrypto.so")
    libc = CDLL("")

    def __init__(self, path):
        fopen = self.libc.fopen
        fopen.restype = c_voidp
        fopen.argtypes = c_char_p, c_char_p
        PEM_read_PrivateKey = self.crypto.PEM_read_PrivateKey
        PEM_read_PrivateKey.restype = c_int
        PEM_read_PrivateKey.argtypes = c_voidp, c_voidp, c_voidp, c_voidp
        DHparams_dup = self.crypto.DHparams_dup
        DHparams_dup.argtypes = (POINTER(dh_st),)
        DHparams_dup.restype = POINTER(dh_st)
        fclose = self.libc.fclose
        fclose.argtypes = (c_voidp,)
        fclose.restype = c_int
        EVP_PKEY_free = self.crypto.EVP_PKEY_free
        EVP_PKEY_free.argtypes = (POINTER(evp_pkey_st),)
        EVP_PKEY_free.restype = c_int
        BN_dup = self.crypto.BN_dup
        BN_dup.argtypes = (c_voidp,)
        BN_dup.restype = c_voidp

        fp = fopen(path, b"r")
        if not fp:
            raise Exception("private key file not found")
        try:
            pk = POINTER(evp_pkey_st)()
            res = PEM_read_PrivateKey(fp, byref(pk), None, None)
        finally:
            fclose(fp)

        try:
            if res == 0 or not pk or not pk.contents.dh:
                raise Exception("PEM file does not look like a private key")
            dh = pk.contents.dh.contents
            if not dh.pub_key or not dh.priv_key or not dh.p or not dh.q or not dh.g:
                raise Exception("PEM file does not look like a private key")
            self.dh = DHparams_dup(dh)
            if not self.dh:
                raise Exception("failed to clone dh")
            self.dh.contents.pub_key = BN_dup(dh.pub_key)
            self.dh.contents.priv_key = BN_dup(dh.priv_key)
        finally:
            EVP_PKEY_free(pk)

        free = self.libc.free
        free.restype = None
        free.argtypes = (c_voidp,)
        self.free = free

        schnorr_sign = self.schnorr.schnorr_sign
        schnorr_sign.argtypes = c_voidp, c_voidp, c_voidp, c_voidp, c_voidp, c_char_p, c_uint, \
                POINTER(POINTER(c_char)), POINTER(c_uint)
        schnorr_sign.restype = c_int
        self.schnorr_sign = schnorr_sign

    def sign_value(self, val):
        val_arr = c_char * len(val)
        val_ = val_arr(*val)
        out = POINTER(c_char)()
        out_len = c_uint(0)
        dh = self.dh.contents
        res = self.schnorr_sign(dh.p, dh.q, dh.g, dh.priv_key, dh.pub_key, val_, len(val),
                                byref(out), byref(out_len))
        if res == -1:
            raise Exception("signature failed")
        out_arr = (c_char * out_len.value).from_address(addressof(out.contents))

        buf = bytes(out_arr)
        self.free(out_arr)
        return buf

    # just for testing that signatures validate correctly
    def verify_signature(self, val, signature):
        val_arr = c_char * len(val)
        val_ = val_arr(*val)

        sig_arr = c_char * len(signature)
        sig = sig_arr(*signature)

        schnorr_verify = self.schnorr.schnorr_verify
        schnorr_verify.restype = c_int
        schnorr_verify.argtypes = c_voidp, c_voidp, c_voidp, c_voidp, val_arr, \
                c_uint, sig_arr, c_uint

        dh = self.dh.contents

        res = schnorr_verify(dh.p, dh.q, dh.g, dh.pub_key, val_, len(val_), sig, len(signature))
        return res == 1

#from binascii import unhexlify
#s = Schnorr(b"privkey_rfc5114.pem")
#v = unhexlify(b"0f827cf805923cd3dd48b97cddc813c6")
#print(s.verify_signature(v, s.sign_value(v)))
#print(s.verify_signature(v, unhexlify(b"00000100333108a5b0ec8ab127258239fba2bbfabaf6f307f292d848144e508d42428e03976789b8192347d9cab24967181b156fe149dda89eb2ed5d5706a0083e08525fc61d58601596fb612b9b7be09c3d4bc15cfacc49e8464e577eb3b896597edd4b3b63c55db1e35c461f6d9de01dc807b36d4e341af0f98d46530d2aedc342eb3a91f9820956d211a1ab6f0e64be71dd12e5b0a1dbdf3a210c53b98ec0dc21120cdc22d0d2c664903952a7de45cc0e6c5dea4a8237054e883760923347c880b8c94002f6a8326a9c060a26b0fa9a7b69726497f5b0039bbba8977662d3a6216dd615a2a00c5415436898124ea86b8beaec4ab7b3373dc3cc36cf2512716ef89ea50000002036fc6a2d97d9b74883294d1af0e855dc7cd18c3bef1fa8604f0c9beecd1a0a1d")))#s.sign_value(v)))

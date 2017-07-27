#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>

#include <openssl/rand.h>
#include <openssl/pem.h>

#include <schnorr.h>
#include <kore/kore.h>

#include "sess.h"
#include "db.h"

bool unhexlify(const char *inp, uint8_t *outp) {
    for (size_t i = 0; inp[i*2] != '\0'; i++) {
        int res = sscanf(inp + i*2, "%02hhx", &outp[i]);
        if (res != 1) {
            fprintf(stderr, "res=%d, i=%lu\n", res, i);
            return false;
        }
    }
    return true;
}


static DH *dh;

__attribute__((constructor))
static void generate_cert(void) {
    struct stat buf;
    int res = stat("cert/server.crt", &buf);
    if (res == 0) {
        res = stat("cert/server.key", &buf);
    }
    if (res == -1 && errno == ENOENT) {
        res = system("[ -n \"`hostname -I`\" ] && openssl req -x509 -newkey rsa:3072 -keyout cert/server.key -out cert/server.crt -days 1 -nodes -sha256 -subj /CN=`hostname -I` -batch");
    }
    if (res != 0) {
        exit(1);
    }
}

__attribute__((constructor))
static void read_pubkey(void) {
    FILE *fp = fopen("pubkey_rfc5114.pem", "r");
    EVP_PKEY *pk = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (pk == NULL || !pk->pkey.dh->pub_key || !pk->pkey.dh->p || !pk->pkey.dh->q || !pk->pkey.dh->g)
        exit(1);
    dh = DHparams_dup(pk->pkey.dh);
    if (!dh)
        exit(1);
    dh->pub_key = BN_dup(pk->pkey.dh->pub_key);
    fclose(fp);

    EVP_PKEY_free(pk);
}

static bool hexlify16(uint8_t inp[16], char outp[33]) {
    for (size_t i = 0; i < 16; i++) {
        int res = snprintf(outp + i*2, 3, "%02hhx", inp[i]);
        if (res != 2) {
            return false;
        }
    }
    return true;
}

bool new_chall(char data[33]) {
	uint8_t buf[16];
	int res = RAND_bytes(buf, sizeof(buf));
	if (res != 1) {
		return false;
	}

	if (!hexlify16(buf, data)) {
		return false;
	}

	return insert_chall(data) == KORE_RESULT_OK;
}

bool validate_chall(const char chall[33], const uint8_t *signature, size_t signature_len) {
	uint8_t data[16];
	unhexlify(chall, data);

	bool found = chall_exists(chall);
	if (!found) {
		return false;
	}

	int res = schnorr_verify(dh->p, dh->q, dh->g, dh->pub_key, data, 16, signature, signature_len);
	return res != 0;
}

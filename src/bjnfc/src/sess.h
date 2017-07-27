#include <stdbool.h>

bool new_chall(char data[33]);
bool validate_chall(const char data[16], const uint8_t *signature, size_t signature_len);

bool unhexlify(const char *inp, uint8_t *outp);


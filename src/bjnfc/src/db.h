#include <stdint.h>

void init_db(void);
int insert_user(const char *email, const char *pass);
int get_devices(const char *email, const char *pass, char *device_names[20], char *reasons[20], uint32_t uids[20]);
int assign_device(const char *email, const char *device_name, const char *reason);
bool chall_exists(const char chall[33]);
int insert_chall(const char chall[33]);

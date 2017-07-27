#include <stdbool.h>
// TODO: error, fatal
#define fatal(fmt, ...) do { fprintf(stderr, fmt, __VA_ARGS__); exit(1); } while(false)
#define error(fmt, ...) do { fprintf(stderr, fmt, __VA_ARGS__); } while(false)

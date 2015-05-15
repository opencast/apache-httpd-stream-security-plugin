#ifndef URL_SIGNING_BASE_64
#define URL_SIGNING_BASE_64
#include <stdint.h>
int base_64_decode(char* b64message, uint8_t** buffer, size_t* length);
#endif

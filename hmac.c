#include <openssl/hmac.h>
#include <stdbool.h>
#include <string.h>
#include "base64.h"

static const int KEY_LENGTH = 32;

bool debugApache = true;
bool debugUnitTests = false;

char *create_signature(char* shouldbekey, char* policy, char** output) {
    // The key to hash
    // TODO use the input key
    char key[] = "0123456789abcdef";
    if (debugUnitTests) {
        printf("HMAC Input: %s\n", policy);
    }
    unsigned char* digest;
    digest = HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)policy, strlen(policy), NULL, NULL);

    char hmacString[KEY_LENGTH];
    int i;
    for(i = 0; i < KEY_LENGTH; i++)
         sprintf(&hmacString[i*2], "%02x", (unsigned int)digest[i]);

    char *hmac = (char *)malloc(strlen(hmacString) * sizeof(char) + 1);
    strcpy(hmac, hmacString);
    // output = &hmac;
    printf("HMAC digest: %s\n", hmac);
    return hmac;
}

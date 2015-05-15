#include <openssl/hmac.h>
#include <string.h>
#include "base64.h"

static const int KEY_LENGTH = 32;

/**
 * Create a signed version of a policy based upon a shared secret.
 * @param key
 *          The key to use as the secret to sign the policy.
 * @param policy
 *          The text to sign.
 * @param output
 *          The pointer to assign the signed policy.
 */
char *create_signature(char* key, char* policy, char** output) {
    unsigned char* digest;
    digest = HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)policy, strlen(policy), NULL, NULL);

    char hmacString[KEY_LENGTH];
    int i;
    for(i = 0; i < KEY_LENGTH; i++)
         sprintf(&hmacString[i*2], "%02x", (unsigned int)digest[i]);

    char *hmac = (char *)malloc(strlen(hmacString) * sizeof(char) + 1);
    strcpy(hmac, hmacString);
    return hmac;
}

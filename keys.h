#ifndef URL_SIGNING_KEYS
#define URL_SIGNING_KEYS
struct SecretKey
{
    char *id;
    char *secret;
};

struct KeyCollection
{
    int count;
    struct SecretKey *secret_keys;
};

void get_key_collection(char *text, struct KeyCollection *secret_key_collection);
char *get_stream_security_keys();
#endif

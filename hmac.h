#ifndef URL_SIGNING_HMAC
#define URL_SIGNING_HMAC
char *create_signature(apr_pool_t *p, char* key, char* policy, char** output);
#endif

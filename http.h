#ifndef URL_SIGNING_HTML
#define URL_SIGNING_HTML
/** Constants for the current status of the resource request. */
static const int BAD_REQUEST = 400;
static const int FORBIDDEN = 403;
static const int GONE = 410;
static const int OK = 200;

// Special code to indicate that everything went good in the current stage.
static const int WORKING = -1;
#endif

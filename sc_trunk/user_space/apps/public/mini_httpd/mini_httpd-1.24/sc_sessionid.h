#ifndef __SC_SESSIONID_H__
#define __SC_SESSIONID_H__

#define SESSIONID_MAGICWORD "sessionid"
#define SESSIONID_LEN 30

/* if client take Autherrization header, then verify session cookie; if not, do not verify. */
int sessionid_verify_sessionid_ok(char *sessionid_in_cookie);

/* only just auth OK, then set session cookie also update the session cookie. */
int sessionid_update_device_sessionid(char *new_sessionid);

char *sessionid_get_sessionid_from_cookie(char *cookie);

int sessionid_valid_local_sessionid();

int sessionid_delete_local_sessionid(const char *whichfunction);

#endif

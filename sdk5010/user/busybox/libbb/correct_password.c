/* vi: set sw=4 ts=4: */
/*
 * Copyright 1989 - 1991, Julianne Frances Haugh <jockgrrl@austin.rr.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Julianne F. Haugh nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JULIE HAUGH AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JULIE HAUGH OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "libbb.h"

#define SC_HACK
#define SC_CFPRINTF(fmt, args...)    do{   FILE *fp=fopen("/dev/console", "a+"); if(fp) {fprintf(fp, "[%s::%s():%d] ", __FILE__, __FUNCTION__, __LINE__);fprintf(fp, fmt, ##args);fclose(fp);}}while(0)

#ifdef SC_HACK
static int pipe_buf(char *command, char *buf, int size)
{
  FILE *fp;
  int len=0;
  int ch;

  if((fp=popen(command, "r"))==NULL)
     return (-1);

  while ((ch = fgetc(fp)) != EOF && len < size)
        buf[len++] = ch;

  buf[len-1] = 0;

  pclose(fp);
  return len;
}

//TODO: avoid command injection...
static int password_hash(char *pass, char *hash, int size)
{
        char cmd[256];
        sprintf(cmd, "/bin/echo -n '%s' | /bin/openssl dgst -sha256 2>/dev/null | /bin/cut -d' ' -f2", pass);
        return pipe_buf(cmd, hash, size);
}
#endif


/* Ask the user for a password.
 * Return 1 if the user gives the correct password for entry PW,
 * 0 if not.  Return 1 without asking if PW has an empty password.
 *
 * NULL pw means "just fake it for login with bad username" */

int FAST_FUNC correct_password(const struct passwd *pw)
{
	char *unencrypted, *encrypted;
	const char *correct;
	int r;
#if ENABLE_FEATURE_SHADOWPASSWDS
	/* Using _r function to avoid pulling in static buffers */
	struct spwd spw;
	char buffer[256];
#endif
#ifdef SC_HACK
	char hash_str[128];
#endif

	/* fake salt. crypt() can choke otherwise. */
	correct = "aa";
	if (!pw) {
		/* "aa" will never match */
		goto fake_it;
	}
	correct = pw->pw_passwd;
#if ENABLE_FEATURE_SHADOWPASSWDS
	if ((correct[0] == 'x' || correct[0] == '*') && !correct[1]) {
		/* getspnam_r may return 0 yet set result to NULL.
		 * At least glibc 2.4 does this. Be extra paranoid here. */
		struct spwd *result = NULL;
		r = getspnam_r(pw->pw_name, &spw, buffer, sizeof(buffer), &result);
		correct = (r || !result) ? "aa" : result->sp_pwdp;
	}
#endif

	if (!correct[0]) /* empty password field? */
		return 1;

 fake_it:
	unencrypted = bb_askpass(0, "Password: ");
	if (!unencrypted) {
		return 0;
	}
#ifndef SC_HACK    	
	encrypted = pw_encrypt(unencrypted, correct, 1);
	r = (strcmp(encrypted, correct) == 0);
	free(encrypted);
	memset(unencrypted, 0, strlen(unencrypted));
#else
	memset(hash_str, 0, sizeof(hash_str));
	password_hash(unencrypted, hash_str, sizeof(hash_str));
	//SC_CFPRINTF("check user:%s, userhash: %s, local:%s\n", unencrypted, hash_str, correct);
    r = (strcmp(unencrypted, correct) == 0); //r = (strncmp(hash_str, correct, 64) == 0);

#endif
	return r;
}

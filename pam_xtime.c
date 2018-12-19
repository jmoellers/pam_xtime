/* pam_xtime module */

/*
 * Written by Josef Möllers, Fujitsu Siemens Computers
 * Version 1.2
 * Based on pam_permit
 *
 * Written by Andrew Morgan <morgan@parc.power.net> 1996/3/11
 *
 * Change Log:
 * 1.0 Initial Revision
 * 1.1 Create new .XTime file with month-specific filename
 *	Also change owner/group of .XTime file.
 * 1.2 Create/Remove ~/.Present when you're coming/going.
 *	This is for external scripts like kommenundgehen.
 *
 * Insert the following line at the very end of /etc/pam.d/xdm:
 * session  optional       /lib/security/pam_xtime.so
 *
 */

#define DEFAULT_USER "nobody"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <syslog.h>

/*
 * here, we make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally) they are used to instruct the
 * modules include file to define their prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

# include	<pwd.h>
# include	<sys/types.h>
# include	<time.h> 
# include	<unistd.h>
static const char logfilename[] = ".XTime";
static const char presentname[] = ".Present";
# define	KOMMEN	'k'
# define	GEHEN	'g'

static void
xtime_log(pam_handle_t *pamh, char reason)
{
    FILE *fp;
    char *username, *pathname;
    struct passwd *pwe;
    time_t now;
    struct tm *tv;

    (void) time(&now);
    tv = localtime(&now);

    pam_get_item(pamh, PAM_USER, (const void **) &username);
    if (username != (char *) NULL)
    {
	pwe = getpwnam(username);
	if (pwe != (struct passwd *) NULL)
	{
	    /* pwe->pw_dir/logfilename.mm.yyyy */
	    pathname = (char *) malloc(strlen(pwe->pw_dir) +
	    			      1 +	/* / */
				      strlen(logfilename) +
				      1 +	/* . */
				      2 +	/* mm */
				      1 +	/* . */
				      4 +	/* yyyy */
				      1		/* \0 */
				      );
	    if (pathname != (char *) NULL)
	    {
		mode_t oldmask;

		sprintf(pathname, "%s/%s.%02d.%04d",
				   pwe->pw_dir,
				      logfilename,
				         tv->tm_mon + 1,
					      tv->tm_year + 1900);
		/*
		 * Make sure the file is neither group- nor
		 * world-accessable
		 */
		oldmask = umask(0);
		(void) umask(oldmask & ~077);
		fp = fopen(pathname, "a");
		if (fp != (FILE *) NULL)
		{
		    fprintf(fp, "%lu %02d.%02d.%04d-%02d:%02d %s\n",
		    	now,
		    	tv->tm_mday, tv->tm_mon+1, tv->tm_year+1900,
			tv->tm_hour, tv->tm_min,
			reason == KOMMEN ? "Kommen" : "Gehen");
		    fchown(fileno(fp), pwe->pw_uid, pwe->pw_gid);
		    fclose(fp);
		}
		free(pathname);
	    }

	    /*
	     * pwe->pw_dir/presentname
	     * The presentfile is just to toggle between Coming and
	     * going if that's difficult to determine, e.g. for an
	     * external script.
	     */
	    pathname = (char *) malloc(strlen(pwe->pw_dir) +
	    			      1 +	/* / */
				      strlen(presentname) +
				      1		/* \0 */
				      );
	    if (pathname != (char *) NULL)
	    {
		mode_t oldmask;

		sprintf(pathname, "%s/%s", pwe->pw_dir, presentname);
		switch (reason)
		{
		case KOMMEN:
		    fclose(fopen(pathname, "w"));
		    break;
		case GEHEN:
		    unlink(pathname);
		    break;
		}
		free(pathname);
	    }
	}
    }
else
{
# if 0 /* { */
    openlog("pam_xtime", 0, LOG_AUTHPRIV);
    syslog(LOG_WARNING, "Cannot determine user name");
    closelog();
# else /* }{ */
    FILE *dst;
    if (dst = fopen("/tmp/pam_xtime.err", "a"))
    {
	fprintf(dst, "pam_xtime: cannot determine user name\n");
	fclose(dst);
    }
# endif /* } */
}
}

/* --- authentication management functions --- */

PAM_EXTERN
int
pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc
                        ,const char **argv)
{
    int retval;
    const char *user=NULL;

    /*
     * authentication requires we know who the user wants to be
     */
    retval = pam_get_user(pamh, &user, NULL);
    if (retval != PAM_SUCCESS) {
        D(("get user returned error: %s", pam_strerror(pamh,retval)));
        return retval;
    }
    if (user == NULL || *user == '\0') {
        D(("username not known"));
        pam_set_item(pamh, PAM_USER, (const void *) DEFAULT_USER);
    }
    user = NULL;                                            /* clean up */

    return PAM_SUCCESS;
}

PAM_EXTERN
int
pam_sm_setcred(pam_handle_t *pamh,int flags,int argc
                   ,const char **argv)
{
     return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN
int
pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc
                     ,const char **argv)
{
     return PAM_SUCCESS;
}

/* --- password management --- */

PAM_EXTERN
int
pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc
                     ,const char **argv)
{
     return PAM_SUCCESS;
}

/* --- session management --- */

PAM_EXTERN
int
pam_sm_open_session(pam_handle_t *pamh,int flags,int argc
                        ,const char **argv)
{
    xtime_log(pamh, KOMMEN);
    return PAM_SUCCESS;
}

PAM_EXTERN
int
pam_sm_close_session(pam_handle_t *pamh,int flags,int argc
                         ,const char **argv)
{
     xtime_log(pamh, GEHEN);
     return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_xtime_modstruct = {
    "pam_xtime",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif

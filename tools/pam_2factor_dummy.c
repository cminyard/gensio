/*******************************************************************************
 * file:        pam_2factor_dummy.c
 * author:      Corey Minyard (base on 2ndfactor.  by ben servoz)
 * description: PAM module to provide an example 2nd factor authentication
 * notes:       This is an example module, if the 2fa code is provided
 *              with the value "dummy", it will be authenticated.
 *              Compile with:
 *                gcc -o pam_2factor_dummy.so -shared pam_2factor_dummy.c
 *              and put in the pam module directory.
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* From pam_unix/support.c */
static int
converse(pam_handle_t *pamh, int nargs, struct pam_message **message,
	 struct pam_response **response)
{
    int retval;
    struct pam_conv *conv;

    retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (retval == PAM_SUCCESS) {
	retval = conv->conv(nargs, (const struct pam_message **) message,
			    response, conv->appdata_ptr);
    }

    return retval;
}


/* expected hook, this is where custom stuff happens */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int retval;
    int i;

    struct pam_message msg[1], *pmsg[1];
    struct pam_response *resp;

    char *input;
    const char *token = "dummy";

    for (i = 0; i < argc; i++) {
	if (strncmp(argv[i], "token=", 6) == 0) {
	    token = argv[i] + 6;
	}
    }

    /* setting up conversation call prompting for one-time code */
    pmsg[0] = &msg[0];
    msg[0].msg_style = PAM_PROMPT_ECHO_ON;
    msg[0].msg = "1-time code: ";
    resp = NULL;
    retval = converse(pamh, 1, pmsg, &resp);
    if (retval != PAM_SUCCESS) {
	return retval;
    }

    /* retrieving user input */
    if (resp) {
	input = resp[0].resp;
	free(resp);
	if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && input == NULL) {
	    return PAM_AUTH_ERR;
	}
    } else {
	return PAM_CONV_ERR;
    }

    if (!input) {
	return PAM_AUTH_ERR;
    }

    if (strcmp(input, token) == 0) {
	retval = PAM_SUCCESS;
    } else {
	retval = PAM_AUTH_ERR;
    }
    memset(input, 0, strlen(input));
    free(input);
    return retval;
}

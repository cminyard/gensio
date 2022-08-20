
#include <stdio.h>

int
main(int argc, char *argv[])
{
    char buf[100];
    size_t len, i;
    int rv = 0;
    int close = 0;

    do {
	len = fread(buf, 1, 1, stdin);
	if (len > 0) {
	    fwrite(buf, 1, len, stdout); fflush(stdout);
	    for (i = 0; i < len; i++) {
		if (buf[i] == 'x')
		    close = 1;
		if (buf[i] == 'e') {
		    rv = 1;
		    close = 1;
		}
	    }
	}
    } while (len > 0 && !close);
    return rv;
}

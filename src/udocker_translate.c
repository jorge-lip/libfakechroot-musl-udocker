#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "dedotdot.h"

#define FAKECHROOT_PATH_MAX 1000


#include <config.h>
#include <sys/types.h>



size_t
strlcpy(char *dst, const char *src, size_t siz)
{
        char *d = dst;
        const char *s = src;
        size_t n = siz;

        /* Copy as many bytes as will fit */
        if (n != 0) {
                while (--n != 0) {
                        if ((*d++ = *s++) == '\0')
                                break;
                }
        }

        /* Not enough room in dst, add NUL and traverse rest of src */
        if (n == 0) {
                if (siz != 0)
                        *d = '\0';              /* NUL-terminate dst */
                while (*s++)
                        ;
        }

        return(s - src - 1);    /* count does not include NUL */
}

void dedotdot(char * file)
{
    char c, *cp, *cp2;
    int l;

    if (!file || !*file)
        return;

    /* Collapse any multiple / sequences. */
    while ((cp = strstr(file, "//")) != (char*) 0) {
        for (cp2 = cp + 2; *cp2 == '/'; ++cp2)
            continue;
        (void) strlcpy(cp + 1, cp2, strlen(cp2) + 1);
    }

    /* Remove leading ./ and any /./ sequences. */
    while (strncmp(file, "./", 2) == 0)
        (void) strlcpy(file, file + 2, strlen(file) - 1);
    while ((cp = strstr(file, "/./")) != (char*) 0)
        (void) strlcpy(cp, cp + 2, strlen(cp) - 1);

    /* Alternate between removing leading ../ and removing foo/../ */
    for (;;) {
        while (strncmp(file, "/../", 4) == 0)
            (void) strlcpy(file, file + 3, strlen(file) - 2);
        cp = strstr(file, "/../");
        if (cp == (char*) 0 || strncmp(file, "../", 3) == 0)
            break;
        for (cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2)
            continue;
        (void) strlcpy(cp2 + 1, cp + 4, strlen(cp) - 3);
    }

    /* Also elide any foo/.. at the end. */
    while (strncmp(file, "../", 3) != 0 && (l = strlen(file)) > 3
            && strcmp((cp = file + l - 3), "/..") == 0) {

        for (cp2 = cp - 1; cp2 > file && *cp2 != '/'; --cp2)
            continue;

        if (cp2 < file)
            break;
        if (strncmp(cp2, "../", 3) == 0)
            break;

        c = *cp2;
        *cp2 = '\0';

        if (file == cp2 && c == '/') {
            strcpy(file, "/");
        }
    }

    /* Correct some paths */
    if (*file == '\0') {
        strcpy(file, ".");
    }
    else if (strcmp(file, "/.") == 0 || strcmp(file, "/..") == 0) {
        strcpy(file, "/");
    }

    /* Any /. and the end */
    for (l = strlen(file); l > 3 && strcmp((cp = file + l - 2), "/.") == 0; l -= 2) {
        *cp = '\0';
    }
}

ssize_t udocker_readlink(const char * path, char * buf, size_t bufsiz)
{
    int linksize;
    char tmp[FAKECHROOT_PATH_MAX], *tmpptr;
    /*
    const char *fakechroot_base = getenv("FAKECHROOT_BASE");
    */

    debug("readlink_udocker(\"%s\", &buf, %zd)", path, bufsiz);
    if (!strcmp(path, "/etc/malloc.conf")) {
        errno = ENOENT;
        return -1;
    }
    expand_chroot_path_orig(path);

    if ((linksize = nextcall(readlink)(path, tmp, FAKECHROOT_PATH_MAX-1)) == -1) {
        return -1;
    }
    tmp[linksize] = '\0';

    if (fakechroot_base != NULL) {
        tmpptr = strstr(tmp, fakechroot_base);
        if (tmpptr != tmp) {
            tmpptr = tmp;
        }
        else if (tmp[strlen(fakechroot_base)] == '\0') {
            tmpptr = "/";
            linksize = strlen(tmpptr);
        }
        else if (tmp[strlen(fakechroot_base)] == '/') {
            tmpptr = tmp + strlen(fakechroot_base);
            linksize -= strlen(fakechroot_base);
        }
        else {
            tmpptr = tmp;
        }
        if (strlen(tmpptr) > bufsiz) {
            linksize = bufsiz;
        }
        strncpy(buf, tmpptr, linksize);
    }
    else {
        strncpy(buf, tmp, linksize);
    }
    return linksize;
}

void udocker_realpath(char *path) {
	char *p, *r, *starti, *endi;
	char resolved[FAKECHROOT_PATH_MAX];
	char linkdata[FAKECHROOT_PATH_MAX];
	char linkpath[FAKECHROOT_PATH_MAX];
	int link_len, resolved_len, finish;

	if (! path || *path == '\0' || *path != '/') {
		return;
	}
	for (finish = 0, p = path, r = resolved;; p = ++endi) {
		for (starti = p; *starti == '/'; starti++);
		if ((r - resolved) + 1 < FAKECHROOT_PATH_MAX) {
			*r++ = '/';
		        *r = '\0';
		} else {
			break;
		}
		if (*starti == '\0') {
			break;
		} 
		for (endi = starti; *endi != '/' && *endi != '\0'; endi++);
		if (*endi == '\0') finish = 1;
		else *endi = '\0';
		resolved_len = r - resolved;
		strlcpy(linkpath, resolved, FAKECHROOT_PATH_MAX);
                strlcpy(linkpath + resolved_len, starti, FAKECHROOT_PATH_MAX - resolved_len);
                if ( (link_len = udocker_readlink(linkpath, linkdata, FAKECHROOT_PATH_MAX)) != -1) {
			linkdata[link_len] = '\0';
			if (*linkdata == '/') r = resolved;
			strlcpy(r, linkdata, FAKECHROOT_PATH_MAX - resolved_len);
		}
		else {
			strlcpy(r, starti, FAKECHROOT_PATH_MAX - resolved_len);
		}
		if (finish) {
		        break;
		}
	        dedotdot(resolved);
	        for (r = resolved; *r != '\0'; r++); 
	}
	strlcpy(path, resolved, FAKECHROOT_PATH_MAX);
}

int main() {
	char resolved[1000];
	char path[1000];
	strcpy(path, "///../home//jorge/tmp/aa/0/aa/0/../tmp/aa/X/");
	printf("translate: %s\n", path);
        udocker_realpath(path, resolved);
	printf("%s\n", resolved);
	exit(1);
}

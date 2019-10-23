/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2010, 2013 Piotr Roszatycki <dexter@debian.org>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
*/


#include <config.h>

#ifdef HAVE_POSIX_SPAWN
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <spawn.h>
#include <stdlib.h>
#include <fcntl.h>
#include <alloca.h>
#include "strchrnul.h"
#include "libfakechroot.h"
#include "open.h"
#include "setenv.h"
#include "readlink.h"


wrapper(posix_spawn, int, (pid_t* pid, const char * filename, 
        const posix_spawn_file_actions_t* file_actions,
        const posix_spawnattr_t* attrp, char* const argv[],
        char * const envp []))
{
    int status;
    int file;
    int is_base_orig = 0;
    char hashbang[FAKECHROOT_PATH_MAX];
    size_t argv_max = 1024;
    const char **newargv = alloca(argv_max * sizeof (const char *));
    char **newenvp, **ep;
    char *key, *env;
    char tmpkey[1024], *tp;
    char *cmdorig;
    char tmp[FAKECHROOT_PATH_MAX];
    char substfilename[FAKECHROOT_PATH_MAX];
    char newfilename[FAKECHROOT_PATH_MAX];
    char argv0[FAKECHROOT_PATH_MAX];
    char *ptr;
    unsigned int i, j, n, newenvppos;
    unsigned int do_cmd_subst = 0;
    size_t sizeenvp;
    char c;

    char *fakechroot_base = fakechroot_preserve_getenv("FAKECHROOT_BASE");
    char *elfloader = getenv("FAKECHROOT_ELFLOADER");
    char *elfloader_opt_argv0 = getenv("FAKECHROOT_ELFLOADER_OPT_ARGV0");
    char *fakechroot_disallow_env_changes = fakechroot_preserve_getenv("FAKECHROOT_DISALLOW_ENV_CHANGES");
    char *fakechroot_library_orig = fakechroot_preserve_getenv("FAKECHROOT_LIBRARY_ORIG");
    int ld_library_real_pos = -1;


    if (elfloader && !*elfloader) elfloader = NULL;
    if (elfloader_opt_argv0 && !*elfloader_opt_argv0) elfloader_opt_argv0 = NULL;

    debug("posix_spawn(\"%s\", {\"%s\", ...}, {\"%s\", ...})", filename, argv[0], envp ? envp[0] : "(null)");

    strncpy(argv0, filename, FAKECHROOT_PATH_MAX);

    /* Substitute command only if FAKECHROOT_CMD_ORIG is not set. Unset variable if it is empty. */
    cmdorig = getenv("FAKECHROOT_CMD_ORIG");
    if (cmdorig == NULL)
        do_cmd_subst = fakechroot_try_cmd_subst(getenv("FAKECHROOT_CMD_SUBST"), argv0, substfilename);
    else if (!*cmdorig)
        unsetenv("FAKECHROOT_CMD_ORIG");

    /* Scan envp and check its size */
    sizeenvp = 0;
    if (envp) {
        for (ep = (char **)envp; *ep != NULL; ++ep) {
            sizeenvp++;
        }
    }

    /* Copy envp to newenvp */
    newenvp = malloc( (sizeenvp + preserve_env_list_count + 1) * sizeof (char *) );
    if (newenvp == NULL) {
        __set_errno(ENOMEM);
        return errno;
    }
    newenvppos = 0;

    /* Create new envp */
    newenvp[newenvppos] = malloc(strlen("FAKECHROOT=true") + 1);
    strcpy(newenvp[newenvppos], "FAKECHROOT=true");
    newenvppos++;

    /* Preserve old environment variables if not overwritten by new */
    for (j = 0; j < preserve_env_list_count; j++) {
        key = preserve_env_list[j];
        env = fakechroot_preserve_getenv(key);
        if (env != NULL && *env) {
            if (do_cmd_subst && strcmp(key, "FAKECHROOT_BASE") == 0) {
                key = "FAKECHROOT_BASE_ORIG";
                is_base_orig = 1;
            }
            if (envp && !fakechroot_disallow_env_changes) {
                for (ep = (char **) envp; *ep != NULL; ++ep) {
                    strncpy(tmpkey, *ep, 1024);
                    tmpkey[1023] = 0;
                    if ((tp = strchr(tmpkey, '=')) != NULL) {
                        *tp = 0;
                        if (strcmp(tmpkey, key) == 0) {
                            goto skip1;
                        }
                    }
                }
            }
            newenvp[newenvppos] = malloc(strlen(key) + strlen(env) + 3);
            if (strcmp(key, "LD_LIBRARY_REAL") == 0)
                ld_library_real_pos = newenvppos;
            strcpy(newenvp[newenvppos], key);
            strcat(newenvp[newenvppos], "=");
            strcat(newenvp[newenvppos], env);
            newenvppos++;
        skip1: ;
        }
    }

    /* Append old envp to new envp */
    if (envp) {
        for (ep = (char **) envp; *ep != NULL; ++ep) {
            strncpy(tmpkey, *ep, 1024);
            tmpkey[1023] = 0;
            if ((tp = strchr(tmpkey, '=')) != NULL) {
                *tp = 0;
                for (j=0; j < newenvppos; j++) {  /* ignoore env vars already added */
                    if (strncmp(newenvp[j], tmpkey, strlen(tmpkey)) == 0) {
                        goto skip2;
                    }
                }
                if (strcmp(tmpkey, "FAKECHROOT") == 0 ||
                    (is_base_orig && strcmp(tmpkey, "FAKECHROOT_BASE") == 0))
                {
                    goto skip2;
                }
                /* broken */
                if (fakechroot_library_orig && ld_library_real_pos != -1 && *(tp+1) != '\0' &&
                       strcmp(tmpkey, "LD_LIBRARY_PATH") == 0) {
                    int newsize, count = 1;
                    char *dir, *iter, *ld_library_real;
                    for (iter = *ep + (tp - tmpkey) + 1; *iter; iter++)
                        if ( *iter == ':') count++; 
                    newsize = sizeof("LD_LIBRARY_REAL=") + strlen(fakechroot_library_orig) +
                              strlen(tp+1) + (count * (strlen(fakechroot_base) + 1)) + 4;
                    free(newenvp[ld_library_real_pos]);
                    ld_library_real = newenvp[ld_library_real_pos] = malloc(newsize);
                    strcpy(ld_library_real, "LD_LIBRARY_REAL=");
                    for (iter = dir = *ep + (tp - tmpkey) + 1; *iter ; iter++) {
                        if (*iter == ':' || *(iter + 1) == 0) {
                            if (*iter == ':') *iter = 0; 
                            strcat(ld_library_real, fakechroot_base);
                            strcat(ld_library_real, "/");
                            strcat(ld_library_real, dir);
                            strcat(ld_library_real, ":");
                            dir = iter + 1; 
                        }
                    }
                    strcat(ld_library_real, fakechroot_library_orig);
                }

            }
            newenvp[newenvppos] = *ep;
            newenvppos++;
        skip2: ;
        }
    }

    newenvp[newenvppos] = NULL;

    if (newenvp == NULL) {
        __set_errno(ENOMEM);
        return errno;
    }

    if (do_cmd_subst) {
        newenvp[newenvppos] = malloc(strlen("FAKECHROOT_CMD_ORIG=") + strlen(filename) + 1);
        strcpy(newenvp[newenvppos], "FAKECHROOT_CMD_ORIG=");
        strcat(newenvp[newenvppos], filename);
        newenvppos++;
    }

    newenvp[newenvppos] = NULL;

    /* Exec substituded command */
    if (do_cmd_subst) {
        debug("nextcall(posix_spawn)(\"%s\", {\"%s\", ...}, {\"%s\", ...})", substfilename, argv[0], newenvp[0]);

        /* Indigo udocker */
        fakechroot_upatch_elf(substfilename);

        status = nextcall(posix_spawn)(pid, substfilename, file_actions, attrp, (char * const *)argv, newenvp);
        goto error;
    }

    /* Check hashbang */
    expand_chroot_path(filename);
    strcpy(tmp, filename);
    filename = tmp;

    if ((file = nextcall(open)(filename, O_RDONLY)) == -1) {
        __set_errno(ENOENT);
        return errno;
    }

    i = read(file, hashbang, FAKECHROOT_PATH_MAX-2);
    close(file);
    if (i == -1) {
        __set_errno(ENOENT);
        return errno;
    }

    /* ELF binary */
    if (hashbang[0] == 127 && hashbang[1] == 'E' && hashbang[2] == 'L' && hashbang[3] == 'F') {

        /* Indigo udocker */
        fakechroot_upatch_elf(filename);

        if (!elfloader) {
            status = nextcall(posix_spawn)(pid, filename, file_actions, attrp, argv, newenvp);
            goto error;
        }

        /* Run via elfloader */
        for (i = 0, n = (elfloader_opt_argv0 ? 3 : 1); argv[i] != NULL && i < argv_max; ) {
            newargv[n++] = argv[i++];
        }

        newargv[n] = 0;

        n = 0;
        newargv[n++] = elfloader;
        if (elfloader_opt_argv0) {
            newargv[n++] = elfloader_opt_argv0;
            newargv[n++] = argv0;
        }
        newargv[n] = filename;

        debug("nextcall(posix_spawn)(\"%s\", {\"%s\", \"%s\", ...}, {\"%s\", ...})", elfloader, newargv[0], newargv[n], newenvp[0]);
        status = nextcall(posix_spawn)(pid, elfloader, file_actions, attrp, (char * const *)newargv, newenvp);
        goto error;
    }

    /* Indigo udocker fix spaces before #! */
    for(j = 0; hashbang[j] == ' ' && j < 16; j++);
    if (j) memmove(hashbang, hashbang + j, i);

    /* For hashbang we must fix argv[0] */
    if (hashbang[0] == '#' && hashbang[1] == '!') {
        hashbang[i] = hashbang[i+1] = 0;
        for (i = j = 2; (hashbang[i] == ' ' || hashbang[i] == '\t') && i < FAKECHROOT_PATH_MAX; i++, j++);
        for (n = 0; i < FAKECHROOT_PATH_MAX; i++) {
            c = hashbang[i];
            if (hashbang[i] == 0 || hashbang[i] == ' ' || hashbang[i] == '\t' || hashbang[i] == '\n') {
                hashbang[i] = 0;
                if (i > j) {
                    if (n == 0) {
                        ptr = &hashbang[j];
                        expand_chroot_path(ptr);
                        strcpy(newfilename, ptr);
                    }
                    newargv[n++] = &hashbang[j];
                }
                j = i + 1;
            }
            if (c == '\n' || c == 0)
                break;
        }
    }
    else {    /* default old behavior no hashbang in first line is shell */
        char *ptr2;
        ptr = ptr2 = "/bin/sh";
        expand_chroot_path(ptr);
        strcpy(newfilename, ptr);
        n = 0;
        newargv[n++] = ptr2;
    }

    newargv[n++] = argv0;

    for (i = 1; argv[i] != NULL && i < argv_max; ) {
        newargv[n++] = argv[i++];
    }

    /* Indigo udocker */
    fakechroot_upatch_elf(newfilename);

    newargv[n] = 0;

    if (!elfloader) {
        status = nextcall(posix_spawn)(pid, newfilename, file_actions, attrp, (char * const *)newargv, newenvp);
        goto error;
    }

    /* Run via elfloader */
    j = elfloader_opt_argv0 ? 3 : 1;
    if (n >= argv_max - 1) {
        n = argv_max - j - 1;
    }
    newargv[n+j] = 0;
    for (i = n; i >= j; i--) {
        newargv[i] = newargv[i-j];
    }
    n = 0;
    newargv[n++] = elfloader;
    if (elfloader_opt_argv0) {
        newargv[n++] = elfloader_opt_argv0;
        newargv[n++] = argv0;
    }
    newargv[n] = newfilename;

    debug("nextcall(posix_spawn)(\"%s\", {\"%s\", \"%s\", \"%s\", ...}, {\"%s\", ...})", elfloader, newargv[0], newargv[1], newargv[n], newenvp[0]);
    status = nextcall(posix_spawn)(pid, elfloader, file_actions, attrp, (char * const *)newargv, newenvp);

error:
    free(newenvp);

    return status;
}

#endif

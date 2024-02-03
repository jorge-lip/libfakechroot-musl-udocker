/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2003-2015 Piotr Roszatycki <dexter@debian.org>
    Copyright (c) 2007 Mark Eichin <eichin@metacarta.com>
    Copyright (c) 2006, 2007 Alexander Shishkin <virtuoso@slind.org>

    klik2 support -- give direct access to a list of directories
    Copyright (c) 2006, 2007 Lionel Tricon <lionel.tricon@free.fr>

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

#define _GNU_SOURCE

#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <dlfcn.h>
#include <alloca.h>

#include "setenv.h"
#include "libfakechroot.h"
#include "getcwd_real.h"
#include "strchrnul.h"
#include "strlcpy.h"

#include "readlink.h"
#include "dedotdot.h"

char * fakechroot_base;
size_t fakechroot_base_len;
int    debug_level;

int lib_init = 0;
int fakechroot_disallow_env_changes = -1;
char *fakechroot_expand_symlinks;

/* Useful to exclude a list of directories or files */
#define EXCLUDE_SIZE 64
char *exclude_list[EXCLUDE_SIZE];
int exclude_length[EXCLUDE_SIZE];
int list_max = 0;

/* Indigo udocker map hostdirs to container dirs */
#define MAPDIR_SIZE 64
int map_list_max = 0;

char *map_host_list[MAPDIR_SIZE];
int map_host_length[MAPDIR_SIZE];

char *map_cont_list[MAPDIR_SIZE];
int map_cont_length[MAPDIR_SIZE];

/* List of environment variables to preserve on clearenv() */
char *preserve_env_list[] = {
    "FAKECHROOT_BASE",
    "FAKECHROOT_CMD_SUBST",
    "FAKECHROOT_DEBUG",
    "FAKECHROOT_DETECT",
    "FAKECHROOT_ELFLOADER",
    "FAKECHROOT_ELFLOADER_OPT_ARGV0",
    "FAKECHROOT_EXCLUDE_PATH",
    "FAKECHROOT_VERSION",
    "FAKEROOTKEY",
    "FAKED_MODE",
    "LD_PRELOAD",
    "LD_LIBRARY_REAL",
    "LD_DEBUG",
    "FAKECHROOT_LIBRARY_ORIG",
    "FAKECHROOT_PATCH_PATCHELF",
    "FAKECHROOT_PATCH_ELFLOADER",
    "FAKECHROOT_DIR_MAP",
    "FAKECHROOT_DISALLOW_ENV_CHANGES",
    "FAKECHROOT_PATCH_LAST_TIME",
    "FAKECHROOT_EXPAND_SYMLINKS"
};

const int preserve_env_list_count = sizeof preserve_env_list / sizeof preserve_env_list[0];

char **preserve_env_values;

LOCAL void fakechroot_preserve_env_values(void);
LOCAL int fakechroot_load_keyval (char * listkey[], char * listval[], int lenkey[], int lenval[], int list_len, char * env_var);
LOCAL void fakechroot_dump_list(char * list[], int length[], int list_len);
LOCAL int fakechroot_load_list (char * list[], int length[], int list_len, char * env_var);


LOCAL int fakechroot_debug (const char *fmt, ...)
{
    int ret;
    char newfmt[2048];

    va_list ap;
    va_start(ap, fmt);

    if (! debug_level)
        return 0;

    sprintf(newfmt, PACKAGE ": %s\n", fmt);

    ret = vfprintf(stderr, newfmt, ap);
    va_end(ap);

    return ret;
}

#include "getcwd.h"

/* Bootstrap the library */
void fakechroot_init (void) CONSTRUCTOR;
void fakechroot_init (void)
{

    if (! lib_init) {

        lib_init = 1;
       
        char *detect = getenv("FAKECHROOT_DETECT");

        if (detect) {
            /* printf causes coredump on FreeBSD */
            if (write(STDOUT_FILENO, PACKAGE, sizeof(PACKAGE)-1) &&
                write(STDOUT_FILENO, " ", 1) &&
                write(STDOUT_FILENO, VERSION, sizeof(VERSION)-1) &&
                write(STDOUT_FILENO, "\n", 1)) { /* -Wunused-result */ }
            _Exit(atoi(detect));
        }

        debug_level = (int) getenv("FAKECHROOT_DEBUG");
        debug("fakechroot_init()");
        fakechroot_base = getenv("FAKECHROOT_BASE");
        fakechroot_base_len = strlen(fakechroot_base);
        fakechroot_expand_symlinks = getenv("FAKECHROOT_EXPAND_SYMLINKS");
        if (fakechroot_expand_symlinks &&
                strstr(fakechroot_expand_symlinks, "false") == fakechroot_expand_symlinks)
                     fakechroot_expand_symlinks = NULL;
        debug("FAKECHROOT_BASE=\"%s\"", fakechroot_base);
        debug("FAKECHROOT_BASE_ORIG=\"%s\"", getenv("FAKECHROOT_BASE_ORIG"));
        debug("FAKECHROOT_CMD_ORIG=\"%s\"", getenv("FAKECHROOT_CMD_ORIG"));

        /* We get a list of directories or files to exclude pass from host to guest */
        list_max = fakechroot_load_list(exclude_list, exclude_length,
                                        EXCLUDE_SIZE, "FAKECHROOT_EXCLUDE_PATH");

        /* We get a list of maps host_dir!container_dir */
        map_list_max = fakechroot_load_keyval (map_host_list, map_cont_list,
                                               map_host_length, map_cont_length,
                                               MAPDIR_SIZE, "FAKECHROOT_DIR_MAP");
        /*
        fakechroot_dump_list(map_host_list, map_host_length, map_list_max);
        fakechroot_dump_list(map_cont_list, map_cont_length, map_list_max);
        */

        __setenv("FAKECHROOT", "true", 1);
        __setenv("FAKECHROOT_VERSION", FAKECHROOT, 1);

        fakechroot_preserve_env_values();
        fakechroot_iniwlib();

        lib_init = 2;
    }
}

LOCAL void fakechroot_preserve_env_values(void)
{
    int j;
    char *key, *val;
    preserve_env_values = malloc(sizeof preserve_env_list);
    for (j = 0; j < preserve_env_list_count; j++) {
        key = preserve_env_list[j];
        val = getenv(key);
        preserve_env_values[j] = 0;
        if (val) {
            preserve_env_values[j] = malloc(strlen(val) + 1);
            strcpy(preserve_env_values[j], val); 
            debug("env %s = %s", preserve_env_list[j], preserve_env_values[j]);
        }
        if (strcmp(key, "FAKECHROOT_DISALLOW_ENV_CHANGES"))
            fakechroot_disallow_env_changes = 1;
    }
}

char * fakechroot_preserve_getenv(char * search_key)
{
    int j;
    if (fakechroot_disallow_env_changes == 1) {
        for (j = 0; j < preserve_env_list_count; j++) {
            if (strcmp(search_key, preserve_env_list[j]) == 0 && preserve_env_values[j])
                return preserve_env_values[j];
        }
        return (char *) NULL;
    }
    else {
        return getenv(search_key);
    }
}

LOCAL int fakechroot_load_list (char * list[], int length[], int list_len, char * env_var)
{
    int list_pos = 0;
    char *env_str = getenv(env_var);

    if (env_str) {
        int i;
        for (i = 0; list_pos < list_len; ) {
            int j;
            for (j = i; env_str[j] != ':' && env_str[j] != '\0'; j++);
            list[list_pos] = malloc(j - i + 2);
            memset(list[list_pos], '\0', j - i + 2);
            strncpy(list[list_pos], &(env_str[i]), j - i);
            length[list_pos] = strlen(list[list_pos]);
            list_pos++;
            if (env_str[j] != ':') break;
            i = j + 1;
        }
    }

    return list_pos;
}

LOCAL int fakechroot_in_list (char * list[], int length[], int list_len, char * search)
{
    int list_pos;

    for (list_pos = 0; list_pos < list_len; list_pos++) {
        if (! strncmp(list[list_pos], search, strlen(list[list_pos]))) 
            return 1;
    }
    return 0;
}

/* Lazily load function */
LOCAL fakechroot_wrapperfn_t fakechroot_loadfunc (struct fakechroot_wrapper * w)
{
    char *msg;
    if (!(w->nextfunc = dlsym(RTLD_NEXT, w->name))) {;
        msg = dlerror();
        fprintf(stderr, "%s: %s: %s\n", PACKAGE, w->name, msg != NULL ? msg : "unresolved symbol");
        exit(EXIT_FAILURE);
    }
    return w->nextfunc;
}

/* Check if path is on exclude list */
LOCAL int fakechroot_localdir (const char * p_path)
{
    char *v_path = (char *)p_path;
    char cwd_path[FAKECHROOT_PATH_MAX];

    if (! p_path)
       return 0;

    if (! lib_init)
        fakechroot_init();

    if (! list_max)
        return 0;

    /* We need to expand relative paths */
    if (p_path[0] != '/') {
        getcwd_real(cwd_path, FAKECHROOT_PATH_MAX);
        int cwd_path_len = strlen(cwd_path);
        int p_path_len = strlen(p_path);
        /* may need to append p_path to cwd_path, as in ismapdir 20171203 */
        if (cwd_path_len + p_path_len < FAKECHROOT_PATH_MAX )
            *(cwd_path + cwd_path_len) = '/';
            *(cwd_path + cwd_path_len + 1) = '\0';
            strlcpy(cwd_path + cwd_path_len, p_path, p_path_len + 1);
        /*
        strlcpy(cwd_path + strlen(cwd_path), "/", FAKECHROOT_PATH_MAX);
        strlcpy(cwd_path + strlen(cwd_path), p_path, FAKECHROOT_PATH_MAX);
        */
        v_path = cwd_path;
        narrow_chroot_path(v_path);
    }

    /* We try to find if we need direct access to a file */
    {
        const size_t len = strlen(v_path);
        int i;

        for (i = 0; i < list_max; i++) {
            if (exclude_length[i] > len ||
                    v_path[exclude_length[i] - 1] != (exclude_list[i])[exclude_length[i] - 1] ||
                    strncmp(exclude_list[i], v_path, exclude_length[i]) != 0) continue;
            if (exclude_length[i] == len || v_path[exclude_length[i]] == '/') return 1;
        }
    }

    return 0;
}

/*
 * Parse the FAKECHROOT_CMD_SUBST environment variable (the first
 * parameter) and if there is a match with filename, return the
 * substitution in cmd_subst.  Returns non-zero if there was a match.
 *
 * FAKECHROOT_CMD_SUBST=cmd=subst:cmd=subst:...
 */
LOCAL int fakechroot_try_cmd_subst (char * env, const char * filename, char * cmd_subst)
{
    int len, len2;
    char *p;

    if (env == NULL || filename == NULL)
        return 0;

    /* cleanup filename */
    dedotdot(filename);

    len = strlen(filename);

    do {
        p = strchrnul(env, ':');

        if (strncmp(env, filename, len) == 0 && env[len] == '=') {
            len2 = p - &env[len+1];
            if (len2 >= FAKECHROOT_PATH_MAX)
                len2 = FAKECHROOT_PATH_MAX - 1;
            strncpy(cmd_subst, &env[len+1], len2);
            cmd_subst[len2] = '\0';
            return 1;
        }

        env = p;
    } while (*env++ != '\0');

    return 0;
}

/*
 * Indigo udocker specific code ************************************************
 */

LOCAL int 
fakechroot_load_keyval (char * listkey[], char * listval[], int lenkey[], int lenval[], int list_len, char * env_var)
{
    int list_pos = 0;
    char *env_str = getenv(env_var);

    if (env_str) {
        int i;
        for (i = 0; list_pos < list_len; ) {
            int j, k;
            for (j = i; env_str[j] != ':' && env_str[j] != '\0'; j++);
            for (k = i; env_str[k] != '!' && k != j; k++);
            listkey[list_pos] = malloc(k - i + 2);
            memset(listkey[list_pos], '\0', k - i + 2);
            strncpy(listkey[list_pos], &(env_str[i]), k - i);
            lenkey[list_pos] = strlen(listkey[list_pos]);
            if (env_str[k] == ':') {
                listval[list_pos] = malloc(k - i + 2);
                memset(listval[list_pos], '\0', k - i + 2);
                strncpy(listval[list_pos], &(env_str[i]), k - i);
                lenval[list_pos] = strlen(listval[list_pos]);
            }
            else if (env_str[k] == '!') {
                listval[list_pos] = malloc(j - k + 1);
                memset(listval[list_pos], '\0', j - k + 1);
                strncpy(listval[list_pos], &(env_str[k+1]), j - k - 1);
                lenval[list_pos] = strlen(listval[list_pos]);
            }
            list_pos++;
            if (env_str[j] == '\0') break;
            i = j + 1;
        }
    }

    return list_pos;
}

/* Check if path is on container mapped directories list */
LOCAL int fakechroot_ismapdir (const char * p_path)
{
    char *v_path = (char *)p_path;
    /*
    char cwd_path[FAKECHROOT_PATH_MAX];
    */

    if (! lib_init)
        fakechroot_init();

    if (! map_list_max)
        return -1;

    if (! p_path)
        return -1;

    /* We need to expand relative paths */
    /*
    if (p_path[0] != '/') {
        getcwd(cwd_path, FAKECHROOT_PATH_MAX);
        strlcpy(cwd_path + strlen(cwd_path), "/", FAKECHROOT_PATH_MAX);
        strlcpy(cwd_path + strlen(cwd_path), p_path, FAKECHROOT_PATH_MAX);
    }
    */

    /* We try to find if we have a mapping to a host file or dir */
    {
        const size_t len = strlen(v_path);
        int i;

        for (i = 0; i < map_list_max; i++) {
            if (map_cont_length[i] > len ||
                    v_path[map_cont_length[i] - 1] != (map_cont_list[i])[map_cont_length[i] - 1] ||
                    strncmp(map_cont_list[i], v_path, map_cont_length[i]) != 0) continue;
            if (map_cont_length[i] == len || v_path[map_cont_length[i]] == '/') {
                debug("fakechroot_ismapdir(%s) matches %s", v_path, map_cont_list[i]);
                return i;
            }
        }
    }

    return -1;
}

/* Replace prefix of path with host path */
LOCAL int fakechroot_getmapdir(const char * p_path, int map_pos, char * resolved)
{
    if (p_path[0] != '/') {
        int len, p_path_len;
        getcwd(resolved, FAKECHROOT_PATH_MAX);
        len = strlen(resolved);
        resolved[len] =  '/';
        p_path_len = strlen(p_path);
        if (len + 1 + p_path_len < FAKECHROOT_PATH_MAX)
            strlcpy(resolved + len + 1, p_path, p_path_len + 1);
    }
    else {
        int p_path_suffix_len;
        p_path_suffix_len = strlen(p_path + map_cont_length[map_pos]);
        strlcpy(resolved, map_host_list[map_pos], map_host_length[map_pos] + 1);
        if (map_host_length[map_pos] + p_path_suffix_len < FAKECHROOT_PATH_MAX)
            strlcpy(resolved + map_host_length[map_pos], p_path + map_cont_length[map_pos], p_path_suffix_len + 1);
    }
    debug("fakechroot_getmapdir(%s) -> %s", p_path, resolved);
    return 1;
}

/* Check if path is in map_host_list */
LOCAL int fakechroot_ishostmapdir (const char * p_path)
{
    char *v_path = (char *)p_path;
    char cwd_path[FAKECHROOT_PATH_MAX];
    size_t len;

    if (! p_path)
        return -1;

    if (! lib_init)
        fakechroot_init();

    if (! map_list_max)
        return -1;

    /* We need to expand relative paths */
    if (p_path[0] != '/') {
        int p_path_len;
        debug("fakechroot_ishostmapdir(%s)", p_path);
        getcwd_real(cwd_path, FAKECHROOT_PATH_MAX);
        v_path = cwd_path;
        len = strlen(v_path);
        v_path[len] = '/';
        p_path_len = strlen(p_path);
        if (len + 1 + p_path_len < FAKECHROOT_PATH_MAX)
            strlcpy(v_path + len + 1, p_path, p_path_len + 1);
    }
    else {
        len = strlen(v_path);
    }
    /* if pathname starts with the container base dir then the
     * pathname is a container directory not a host volume
     */
    if (! strncmp(v_path, fakechroot_base, fakechroot_base_len))
        return -1;

    /* We try to find if we have a mapping to a host file or dir */
    {
        int i;

        for (i = 0; i < map_list_max; i++) {
            if (map_host_length[i] > len ||
                    v_path[map_host_length[i] - 1] != (map_host_list[i])[map_host_length[i] - 1] ||
                    strncmp(map_host_list[i], v_path, map_host_length[i]) != 0) continue;
            if (map_host_length[i] == len || v_path[map_host_length[i]] == '/') {
                debug("fakechroot_ishostmapdir(%s) matches %s", v_path, map_host_list[i]);
                return i;
            }
        }
    }
    return -1;
}

/* Replace prefix of path with cont path */
LOCAL int fakechroot_getcontmapdir(const char * p_path, int map_pos, char * resolved)
{
    int p_path_suffix_len = strlen(p_path + map_host_length[map_pos]);
    strlcpy(resolved, map_cont_list[map_pos], map_cont_length[map_pos] + 1);
    if (map_cont_length[map_pos] + p_path_suffix_len < FAKECHROOT_PATH_MAX)
        strlcpy(resolved + map_cont_length[map_pos], p_path + map_host_length[map_pos], p_path_suffix_len + 1);
    debug("fakechroot_getcontmapdir(%s) -> %s", p_path, resolved);
    return 1;
}

/* Dump a list content */
LOCAL void fakechroot_dump_list(char * list[], int length[], int list_len)
{
    int list_pos;

    for (list_pos = 0; list_pos < list_len; list_pos++) {
        debug("%d=\"%s\" : %d", list_pos, list[list_pos], length[list_pos]);
    }
}


/* 
 * Indigo udocker REAL PATHNAMES FIXING LINKS TRANSLATING SYMBOLIC LINKS 
 * path: path to be translated
 * llink: 0 translate all symlinks, 1 do not translate the last element of the path
 */

char * udocker_realpath(const char *path, char *resolved, int llink) {

    if ((! fakechroot_expand_symlinks) || (! path) || *path == '\0' || *path != '/') {
         return path;
    }

    char *p, *r, *l, *starti, *endi;
    char linkdata[FAKECHROOT_PATH_MAX];
    int link_len, resolved_len, filename_len, finish, has_dotdot = 0;

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
        filename_len = endi - starti;
        resolved_len = r - resolved;
        if (resolved_len + filename_len + 1 > FAKECHROOT_PATH_MAX) return path;
        strlcpy(r, starti, filename_len + 1);
        if (*endi == '\0') {
            if (llink) break;
            finish = 1;
        }
        if ( (link_len = udocker_readlink(resolved, linkdata, FAKECHROOT_PATH_MAX)) != -1) {
            linkdata[link_len] = '\0';
            if (*linkdata == '/') {
                r = resolved;
                has_dotdot = 1;
            }
            else if (*linkdata == '.' && *(linkdata + 1) == '.') {
                has_dotdot = 1;
            }
            if (resolved_len + link_len + 1 > FAKECHROOT_PATH_MAX) return path;
            strlcpy(r, linkdata, link_len + 1);
        }
        if (finish) {
            break;
        }
        for (r = resolved; *r != '\0'; r++);
    }
    if (has_dotdot) {
        dedotdot(resolved);
        return resolved;
    }
    return path;
}


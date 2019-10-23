/*
    libfakechroot -- fake chroot environment
    Copyright (c) 2010-2015 Piotr Roszatycki <dexter@debian.org>

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

#ifndef __LIBFAKECHROOT_H
#define __LIBFAKECHROOT_H

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "rel2abs.h"
#include "rel2absat.h"


#define debug fakechroot_debug

char * fakechroot_base;
size_t fakechroot_base_len;
int    debug_level;

#ifdef HAVE___ATTRIBUTE__VISIBILITY
# define LOCAL __attribute__((visibility("hidden")))
#else
# define LOCAL
#endif

#ifdef HAVE___ATTRIBUTE__CONSTRUCTOR
# define CONSTRUCTOR __attribute__((constructor))
#else
# define CONSTRUCTOR
#endif

#ifdef HAVE___ATTRIBUTE__SECTION_DATA_FAKECHROOT
# define SECTION_DATA_FAKECHROOT __attribute__((section("data.fakechroot")))
#else
# define SECTION_DATA_FAKECHROOT
#endif

#if defined(PATH_MAX)
# define FAKECHROOT_PATH_MAX PATH_MAX
#elif defined(_POSIX_PATH_MAX)
# define FAKECHROOT_PATH_MAX _POSIX_PATH_MAX
#elif defined(MAXPATHLEN)
# define FAKECHROOT_PATH_MAX MAXPATHLEN
#else
# define FAKECHROOT_PATH_MAX 2048
#endif

#ifndef UNIX_PATH_MAX
# define UNIX_PATH_MAX 108
#endif


#ifdef AF_UNIX
# ifndef SUN_LEN
#  define SUN_LEN(su) (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
# endif
#endif

#ifndef __set_errno
# define __set_errno(e) (errno = (e))
#endif

#ifndef HAVE_VFORK
# define vfork fork
#endif


/* Indigo udocker */
/* convert a host path to a path relative to the container base dir (udocker) */
#define udocker_host_narrow_chroot_path(path) \
    { \
        if ((path) != NULL && *((char *)(path)) != '\0') { \
            int map_pos; \
            if ((map_pos = fakechroot_ishostmapdir((path))) != -1) { \
                char fakechroot_buf[FAKECHROOT_PATH_MAX]; \
                if (fakechroot_getcontmapdir((path), map_pos, fakechroot_buf)) \
                    memmove((void *)(path), fakechroot_buf, strlen(fakechroot_buf) + 1); \
            } \
            else { \
                if (fakechroot_base != NULL) { \
                    char *fakechroot_ptr = strstr((path), fakechroot_base); \
                    if (fakechroot_ptr == (path)) { \
                        const size_t path_len = strlen(path); \
                        if (path_len == fakechroot_base_len) { \
                            ((char *)(path))[0] = '/'; \
                            ((char *)(path))[1] = '\0'; \
                        } \
                        else if ( ((char *)(path))[fakechroot_base_len] == '/' ) { \
                            memmove((void *)(path), (path) + fakechroot_base_len, 1 + path_len - fakechroot_base_len); \
                        } \
                    } \
                } \
            } \
        } \
    }

/* convert path to relative to the container base dir (original implementation) */
#define narrow_chroot_path(path) \
    { \
        if ((path) != NULL && *((char *)(path)) != '\0') { \
            if (fakechroot_base != NULL) { \
                char *fakechroot_ptr = strstr((path), fakechroot_base); \
                if (fakechroot_ptr == (path)) { \
                    const size_t path_len = strlen(path); \
                    if (path_len == fakechroot_base_len) { \
                        ((char *)(path))[0] = '/'; \
                        ((char *)(path))[1] = '\0'; \
                    } \
                    else if ( ((char *)(path))[fakechroot_base_len] == '/' ) { \
                        memmove((void *)(path), (path) + fakechroot_base_len, 1 + path_len - fakechroot_base_len); \
                    } \
                } \
            } \
        } \
    }

/* Indigo udocker */
/* convert container path to host absolute path */
#define expand_chroot_rel_path_orig(path) \
    { \
        if (!fakechroot_localdir(path)) { \
            int map_pos; \
            if ((map_pos = fakechroot_ismapdir(path)) != -1) { \
                char fakechroot_buf[FAKECHROOT_PATH_MAX]; \
                if (fakechroot_getmapdir((path), map_pos, fakechroot_buf)) \
                    (path) = fakechroot_buf; \
            } \
            else if ((path) != NULL && *((char *)(path)) == '/') { \
                if (fakechroot_base != NULL ) { \
                    char fakechroot_buf[FAKECHROOT_PATH_MAX]; \
                    char *fakechroot_ptr = strstr((path), fakechroot_base); \
                    if (fakechroot_ptr != (path)) { \
                        snprintf(fakechroot_buf, FAKECHROOT_PATH_MAX, "%s%s", fakechroot_base, (path)); \
                        (path) = fakechroot_buf; \
                    } \
                } \
            } \
        } \
    }

/* Indigo udocker */
/* convert relative container path to host absolute path */
/* original libfakechroot code without udocker_realpath call */
#define expand_chroot_path_orig(path) \
    { \
        if (!fakechroot_localdir(path)) { \
            if ((path) != NULL) { \
                char fakechroot_abspath[FAKECHROOT_PATH_MAX]; \
                rel2abs((path), fakechroot_abspath); \
                (path) = fakechroot_abspath; \
                expand_chroot_rel_path_orig(path); \
            } \
        } \
    }

/* Indigo udocker */
/* convert container path to host absolute path */
#define expand_chroot_rel_path(path) \
    { \
        char buffer[FAKECHROOT_PATH_MAX]; char *resolved; \
        resolved = udocker_realpath((path), buffer, 0); \
        if (!fakechroot_localdir(resolved)) { \
            int map_pos; \
            if ((map_pos = fakechroot_ismapdir(resolved)) != -1) { \
                char fakechroot_buf[FAKECHROOT_PATH_MAX]; \
                if (fakechroot_getmapdir((resolved), map_pos, fakechroot_buf)) \
                    (path) = fakechroot_buf; \
            } \
            else if ((resolved) != NULL && *((char *)(resolved)) == '/') { \
                if (fakechroot_base != NULL ) { \
                    char fakechroot_buf[FAKECHROOT_PATH_MAX]; \
                    char *fakechroot_ptr = strstr((resolved), fakechroot_base); \
                    if (fakechroot_ptr != (resolved)) { \
                        snprintf(fakechroot_buf, FAKECHROOT_PATH_MAX, "%s%s", fakechroot_base, (resolved)); \
                        (path) = fakechroot_buf; \
                    } \
                } \
            } \
        } \
    }

/* convert relative container path to host absolute path */
#define expand_chroot_path(path) \
    { \
        if (!fakechroot_localdir(path)) { \
            if ((path) != NULL) { \
                char fakechroot_abspath[FAKECHROOT_PATH_MAX]; \
                rel2abs((path), fakechroot_abspath); \
                (path) = fakechroot_abspath; \
                expand_chroot_rel_path(path); \
            } \
        } \
    }

/* Indigo udocker */
/* convert relative container path to host absolute path */
#define expand_chroot_path_at(dirfd, path) \
    { \
        if (!fakechroot_localdir(path)) { \
            if ((path) != NULL) { \
                char fakechroot_abspath[FAKECHROOT_PATH_MAX]; \
                rel2absat(dirfd, (path), fakechroot_abspath); \
                (path) = fakechroot_abspath; \
                expand_chroot_rel_path(path); \
            } \
        } \
    }


/* Indigo udocker */
/* convert container path to host absolute path */
#define l_expand_chroot_rel_path(path) \
    { \
        char buffer[FAKECHROOT_PATH_MAX]; char *resolved; \
        resolved = udocker_realpath((path), buffer, 1); \
        if (!fakechroot_localdir(resolved)) { \
            int map_pos; \
            if ((map_pos = fakechroot_ismapdir(resolved)) != -1) { \
                char fakechroot_buf[FAKECHROOT_PATH_MAX]; \
                if (fakechroot_getmapdir((resolved), map_pos, fakechroot_buf)) \
                    (path) = fakechroot_buf; \
            } \
            else if ((resolved) != NULL && *((char *)(resolved)) == '/') { \
                if (fakechroot_base != NULL ) { \
                    char fakechroot_buf[FAKECHROOT_PATH_MAX]; \
                    char *fakechroot_ptr = strstr((resolved), fakechroot_base); \
                    if (fakechroot_ptr != (resolved)) { \
                        snprintf(fakechroot_buf, FAKECHROOT_PATH_MAX, "%s%s", fakechroot_base, (resolved)); \
                        (path) = fakechroot_buf; \
                    } \
                } \
            } \
        } \
    }

/* convert relative container path to host absolute path */
#define l_expand_chroot_path(path) \
    { \
        if (!fakechroot_localdir(path)) { \
            if ((path) != NULL) { \
                char fakechroot_abspath[FAKECHROOT_PATH_MAX]; \
                rel2abs((path), fakechroot_abspath); \
                (path) = fakechroot_abspath; \
                l_expand_chroot_rel_path(path); \
            } \
        } \
    }

/* Indigo udocker */
/* convert relative container path to host absolute path */
#define l_expand_chroot_path_at(dirfd, path) \
    { \
        if (!fakechroot_localdir(path)) { \
            if ((path) != NULL) { \
                char fakechroot_abspath[FAKECHROOT_PATH_MAX]; \
                rel2absat(dirfd, (path), fakechroot_abspath); \
                (path) = fakechroot_abspath; \
                l_expand_chroot_rel_path(path); \
            } \
        } \
    }


#define wrapper_decl_proto(function) \
    extern LOCAL struct fakechroot_wrapper fakechroot_##function##_wrapper_decl SECTION_DATA_FAKECHROOT

#define wrapper_decl(function) \
    LOCAL struct fakechroot_wrapper fakechroot_##function##_wrapper_decl SECTION_DATA_FAKECHROOT = { \
        (fakechroot_wrapperfn_t) function, \
        NULL, \
        #function \
    }

#define wrapper_fn_t(function, return_type, arguments) \
    typedef return_type (*fakechroot_##function##_fn_t) arguments

#define wrapper_proto(function, return_type, arguments) \
    extern return_type function arguments; \
    wrapper_fn_t(function, return_type, arguments); \
    wrapper_decl_proto(function)

#if __USE_FORTIFY_LEVEL > 0 && defined __extern_always_inline && defined __va_arg_pack_len
# define wrapper_fn_name(function) __##function##_alias
# define wrapper_proto_alias(function, return_type, arguments) \
    extern return_type __REDIRECT (wrapper_fn_name(function), arguments, function); \
    wrapper_fn_t(function, return_type, arguments); \
    wrapper_decl_proto(function)
#else
# define wrapper_fn_name(function) function
# define wrapper_proto_alias(function, return_type, arguments) \
    wrapper_proto(function, return_type, arguments)
#endif

#define wrapper(function, return_type, arguments) \
    wrapper_proto(function, return_type, arguments); \
    wrapper_decl(function); \
    return_type function arguments

#define wrapper_alias(function, return_type, arguments) \
    wrapper_proto_alias(function, return_type, arguments); \
    wrapper_decl(function); \
    return_type wrapper_fn_name(function) arguments

#define nextcall(function) \
    ( \
      (fakechroot_##function##_fn_t)( \
          fakechroot_##function##_wrapper_decl.nextfunc ? \
          fakechroot_##function##_wrapper_decl.nextfunc : \
          fakechroot_loadfunc(&fakechroot_##function##_wrapper_decl) \
      ) \
    )

#ifdef __clang__
# if __clang_major > 4 || __clang_major__ == 3 && __clang_minor__ >= 6
#  pragma clang diagnostic ignored "-Wpointer-bool-conversion"
# endif
#endif


typedef void (*fakechroot_wrapperfn_t)(void);

struct fakechroot_wrapper {
    fakechroot_wrapperfn_t func;
    fakechroot_wrapperfn_t nextfunc;
    const char *name;
};

extern char *preserve_env_list[];
extern char **preserve_env_values;
extern const int preserve_env_list_count;

int fakechroot_debug (const char *, ...);
fakechroot_wrapperfn_t fakechroot_loadfunc (struct fakechroot_wrapper *);
int fakechroot_localdir (const char *);
int fakechroot_try_cmd_subst (char *, const char *, char *);


/* We don't want to define _BSD_SOURCE and _DEFAULT_SOURCE and include stdio.h */
int snprintf(char *, size_t, const char *, ...);

/* Indigo udocker */
int fakechroot_getmapdir(const char * p_path, int map_pos, char * resolved);
int fakechroot_ismapdir (const char * p_path);
char * fakechroot_preserve_getenv(char * search_key);
int fakechroot_getcontmapdir(const char * p_path, int map_pos, char * resolved);
int fakechroot_ishostmapdir (const char * p_path);
void fakechroot_iniwlib(void);
int fakechroot_addwlib(const int fd, char * wlibnam);
int fakechroot_iswlib(const int fd, char ** wlibnam);
int fakechroot_upatch_elf(const char * filename);
char * udocker_realpath(const char * path, char * resolved, int llink);

#endif


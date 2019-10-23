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

#ifdef HAVE_OPENAT

#define _ATFILE_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <fcntl.h>
#include "libfakechroot.h"


wrapper_alias(openat, int, (int dirfd, const char * pathname, int flags, ...))
{
    int mode = 0;
    int fd;

    va_list arg;
    va_start(arg, flags);

    debug("openat(%d, \"%s\", %d, ...)", dirfd, pathname, flags);
    if (flags & O_NOFOLLOW) {
        l_expand_chroot_path_at(dirfd, pathname);
    }
    else {
        expand_chroot_path_at(dirfd, pathname);
    }
/*
    debug("openat expanded (%s)", pathname);
*/
    if (flags & O_CREAT) {
        mode = va_arg(arg, int);
        va_end(arg);
    }

    fd = nextcall(openat)(dirfd, pathname, flags, mode);
    /* udocker */
    if (fd != -1 && flags & (O_CREAT | O_WRONLY))
        fakechroot_addwlib(fd, 0);

    return fd;
}

#else
typedef int empty_translation_unit;
#endif

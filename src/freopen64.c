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

#ifdef HAVE_FREOPEN64

#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <string.h>
#include "libfakechroot.h"

#ifdef freopen64
#undef freopen64
#endif

wrapper(freopen64, FILE *, (const char *path, const char *mode, FILE *stream))
{
    FILE *fp;
    int fd;

    debug("freopen64(\"%s\", \"%s\", &stream)", path, mode);
    expand_chroot_path(path);
    fp = nextcall(freopen64)(path, mode, stream);

    /* udocker */
    if (fp && mode && (fd = fileno(fp)) != -1 && strstr(mode, "w"))
        fakechroot_addwlib(fd, (char *) path);

    return fp;
}

#else
typedef int empty_translation_unit;
#endif

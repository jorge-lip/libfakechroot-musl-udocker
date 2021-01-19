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

/* udocker */

#include <config.h>

#include <unistd.h>
#include "libfakechroot.h"

wrapper_alias(close, int, (int fd))
{
    int close_status;
    char *filename = (char *) 0; 

    debug("close(%d)", fd); 
    close_status = nextcall(close)(fd);

    if ((close_status == 0) && fakechroot_iswlib(fd, &filename)) {
        fakechroot_upatch_elf(filename);
        free(filename);
    }

    return close_status;
}
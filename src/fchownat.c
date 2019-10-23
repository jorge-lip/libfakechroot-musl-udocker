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

#ifdef HAVE_FCHOWNAT

#define _ATFILE_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "libfakechroot.h"


wrapper(fchownat, int, (int dirfd, const char * path, uid_t owner, gid_t group, int flag))
{
    debug("fchownat(%d, \"%s\", %d, %d, %d)", dirfd, path, owner, group, flag);
    if (flag & AT_SYMLINK_NOFOLLOW) {
    	l_expand_chroot_path_at(dirfd, path);
    }
    else {
    	expand_chroot_path_at(dirfd, path);
    }
    return nextcall(fchownat)(dirfd, path, owner, group, flag);
}

#else
typedef int empty_translation_unit;
#endif

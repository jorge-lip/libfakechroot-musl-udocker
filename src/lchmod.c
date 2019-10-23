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

#ifdef HAVE_LCHMOD

#include <sys/types.h>
#include <sys/stat.h>
#include "libfakechroot.h"


wrapper(lchmod, int, (const char * path, mode_t mode))
{
    debug("lchmod(\"%s\", 0%o)", path, mode);
    l_expand_chroot_path(path);
    return nextcall(lchmod)(path, mode);
}

#else
typedef int empty_translation_unit;
#endif

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

/*
#ifndef HAVE___LXSTAT
*/

#include <sys/stat.h>
#include <unistd.h>
#include "libfakechroot.h"
#include "lstat.h"


wrapper(lstat, int, (const char * filename, struct stat * buf))
{
    int retval;
    const char *orig;    

    debug("lstat(\"%s\", &buf)", filename);

    /*
    char resolved[FAKECHROOT_PATH_MAX];
    if (rel2abs(filename, resolved) == NULL) {
        return -1;
    }
    filename = resolved;
    */

    orig = filename;
    l_expand_chroot_path(filename);
    retval = nextcall(lstat)(filename, buf);
    /* deal with http://bugs.debian.org/561991 */
    char tmp[FAKECHROOT_PATH_MAX];
    READLINK_TYPE_RETURN status;
    if ((buf->st_mode & S_IFMT) == S_IFLNK)
        if ((status = readlink(orig, tmp, sizeof(tmp)-1)) != -1)
            buf->st_size = status;
    return retval;
}


/* Prevent looping with realpath() */
LOCAL int lstat_rel(const char * file_name, struct stat * buf)
{
    int retval;
    const char *orig;

    debug("lstat_rel(\"%s\", &buf)", file_name);
    orig = file_name;
    l_expand_chroot_rel_path(file_name);
    debug("lstat_rel(\"%s\", &buf) = %s", orig, file_name);
    retval = nextcall(lstat)(file_name, buf);
    /* deal with http://bugs.debian.org/561991 */
    char tmp[FAKECHROOT_PATH_MAX];
    READLINK_TYPE_RETURN status;
    if ((buf->st_mode & S_IFMT) == S_IFLNK)
        if ((status = readlink(orig, tmp, sizeof(tmp)-1)) != -1)
            buf->st_size = status;
    return retval;
}





/*
#else
typedef int empty_translation_unit;
#endif
*/




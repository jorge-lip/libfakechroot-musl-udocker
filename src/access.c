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

#include <stdio.h>
#include <fcntl.h>

#include "libfakechroot.h"

int openmpi_ini_done = 1;
int access_first_call = 1;

/*
 * alternate implementation for access() 
 * during openmpi initialization we get called by openmpi at
 * a point where openmpi redefined functions are not yet
 * available (e.g. malloc) also calling dlsym will not work
 */
int alt_access(const char * pathname, int mode)
{
    char *existing_files = getenv("FAKECHROOT_ACCESS_FILESOK");
    if (existing_files) {
        char *match;
        int p_len = strlen(pathname);
        if ((match = strstr(existing_files, pathname)) &&
            (*(match + p_len) == '\0' || *(match + p_len) == ':') &&
            (match == existing_files || *(match - 1) == ':')) {
                debug("alt_access: FOUND %s\n", pathname);
                return 0; /* if pathname in env var then return found */
        }
    }
    debug("alt_access: NOT FOUND %s\n", pathname);
    return -1;
}

wrapper(access, int, (const char * pathname, int mode))
{
    debug("access(\"%s\", %d)", pathname, mode);

/*
    printf("access: %s %d\n", pathname, (long) malloc);
*/
    if (access_first_call) {
        access_first_call = 0;
        if (strcmp(pathname, "/sys/class/infiniband") == 0 && !mode) {
            openmpi_ini_done = 0;
            return alt_access(pathname, mode);
        }
    }

    if (! openmpi_ini_done) {
        if (strncmp(pathname, "/dev/", 5) == 0) {
            return alt_access(pathname, mode);
        }
        else {
            openmpi_ini_done = 1;
        }
    }

    if (mode & AT_SYMLINK_NOFOLLOW) {
        l_expand_chroot_path(pathname);
    }
    else {
        expand_chroot_path(pathname);
    }

    return nextcall(access)(pathname, mode);
}

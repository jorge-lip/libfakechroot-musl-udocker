/*
    udocker -- run containers in user space
    Copyright (c) 2016 Jorge Gomes <jorge@lip.pt>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <limits.h>

#include <config.h>

#include "libfakechroot.h"
#include "strlcpy.h"

#ifdef STANDALONE
#undef  debug
#define debug(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__); fputc('\n', stderr);
#endif

static int    patch_init = 0;
static time_t patch_last_time = 0;

static char * patch_patchelf;
static char * patch_rpath;
static char * patch_base;
static char   patch_elfloader[PATH_MAX];

static int    patch_patchelf_len = 0;
static int    patch_elfloader_len = 0;
static int    patch_rpath_len = 0;
static int    patch_base_len = 0;

static char   print_interpreter[] = "--print-interpreter";
static char   set_interpreter[] = "--set-interpreter";
static char   print_rpath[] = "--print-rpath";
static char   set_rpath[] = "--set-rpath";
static char   set_root_prefix[] = "--set-root-prefix";
static char   restore_root_prefix[] = "--restore-root-prefix";
static char   quiet_mode[] = "-q";

static int    print_interpreter_len = sizeof(print_interpreter) -1;
static int    set_interpreter_len = sizeof(set_interpreter) -1;
static int    print_rpath_len = sizeof(print_rpath) -1;
static int    set_rpath_len = sizeof(set_rpath) -1;

int           (*next_execve)(const char *, char *const [], char *const []);
char        * (*next_realpath)(const char *, char *);
ssize_t       (*next_readlink)(const char *, char *, size_t);
int           (*next_stat)(const char *, struct stat *);

/* track changes to sharable libraries */
#define MAPWLIB_SIZE 64
int map_wlib_max = -1;
char *map_wlibnam_list[MAPWLIB_SIZE];
int map_wlibfd_list[MAPWLIB_SIZE];

LOCAL void
fakechroot_patch_loadfuncs()
{

#ifdef STANDALONE
    if (! (next_realpath = dlsym(RTLD_DEFAULT, "realpath"))) {
#else
    if (! (next_realpath = dlsym(RTLD_NEXT, "realpath"))) {
#endif
        char *msg;
        msg = dlerror();
        debug("%s: %s: %s\n", PACKAGE, "realpath", msg != NULL ? msg : "unresolved symbol");
        exit(EXIT_FAILURE);
    }

#ifdef STANDALONE
    if (! (next_execve = dlsym(RTLD_DEFAULT, "execve"))) {
#else
    if (! (next_execve = dlsym(RTLD_NEXT, "execve"))) {
#endif
        char *msg;
        msg = dlerror();
        debug("%s: %s: %s\n", PACKAGE, "execve", msg != NULL ? msg : "unresolved symbol");
        exit(EXIT_FAILURE);
    }

#ifdef STANDALONE
    if (! (next_readlink = dlsym(RTLD_DEFAULT, "readlink"))) {
#else
    if (! (next_readlink = dlsym(RTLD_NEXT, "readlink"))) {
#endif
        char *msg;
        msg = dlerror();
        debug("%s: %s: %s\n", PACKAGE, "readlink", msg != NULL ? msg : "unresolved symbol");
        exit(EXIT_FAILURE);
    }

#ifdef STANDALONE
    if (! (next_stat = dlsym(RTLD_DEFAULT, "stat"))) {
#else
    if (! (next_stat = dlsym(RTLD_NEXT, "stat"))) {
#endif
        char *msg;
        msg = dlerror();
        debug("%s: %s: %s\n", PACKAGE, "stat", msg != NULL ? msg : "unresolved symbol");
        exit(EXIT_FAILURE);
    }
}

int
fakechroot_patch_init()
{
    char *tmp_elfloader;
    char *tmp_patch_last_time;

    if (! patch_init) {
        patch_init = 1;

        debug("patch init");
        fakechroot_patch_loadfuncs();

        tmp_elfloader = 0;
        if (! ((patch_patchelf = getenv("FAKECHROOT_PATCH_PATCHELF")) &&
               (patch_base = getenv("FAKECHROOT_BASE")) &&
               (tmp_elfloader = getenv("FAKECHROOT_PATCH_ELFLOADER")) ) )
            goto error;

        if (*tmp_elfloader == '/' && next_realpath(tmp_elfloader, patch_elfloader) == NULL)
            goto error;

        patch_rpath = getenv("FAKECHROOT_PATCH_RPATH");

        if (tmp_patch_last_time = getenv("FAKECHROOT_PATCH_LAST_TIME")) {
            sscanf((const char *) tmp_patch_last_time, "%lu", &patch_last_time);
        }

        patch_base_len = strlen(patch_base);

        char *b;
        for(b = patch_base + patch_base_len; b >= patch_base; b--) {
            if (*b == '/' || *b == '\0' || *b == ' ') 
                *b = '\0'; /* remove trailing slashes from base_path */
            else 
                break;
        }

        patch_base_len = strlen(patch_base);
        patch_patchelf_len = strlen(patch_patchelf);
        patch_elfloader_len = strlen(patch_elfloader);
        if (patch_rpath)
            patch_rpath_len = strlen(patch_rpath);

        if (patch_base_len >= PATH_MAX ||
            patch_patchelf_len >= PATH_MAX ||
            patch_elfloader_len >= PATH_MAX ||
            patch_rpath_len >= PATH_MAX)      {
               debug("invalid environment variables length check _PATCH_"); 
               goto error;
        }

        return patch_init = 2;

    }
error:
    patch_init = 2;
    patch_patchelf = 0;
    return 0;
}

LOCAL int
fakechroot_execute(char *buffer, char *cmd, char *args[])
{
    int link[2];
    pid_t pid;
    int len = 0;

    if (pipe(link) == -1)
        return -1;

    if ((pid = fork()) == -1) {
        return -1;

    } else if (! pid) {

        dup2(link[1], STDOUT_FILENO);
        close(link[0]);
        close(link[1]);
        char *env[] = { NULL };
        debug("fakechroot_execute (\"%s\")", cmd);
        next_execve(cmd, args, env);
        exit(1);

    } else {

        int status = 0;
        close(link[1]);
        if (buffer) {
            if ((len = read(link[0], buffer, PATH_MAX -1)) > -1)
                buffer[len] = '\0';
        }

        waitpid(pid, &status, 0);
        close(link[0]);
        if (! WIFEXITED(status))
            return -1;

    }
    return len;
}

LOCAL int
fakechroot_get_interpreter(char *interpreter, char *filename)
{
    char buffer[PATH_MAX];
    int len;

    debug("get_interpreter(\"%s\")", filename); 

    *interpreter = '\0';

    if (! patch_patchelf )
        return 0;

    char *args[] = { patch_patchelf, print_interpreter, filename, NULL };
    if ((len = fakechroot_execute(buffer, patch_patchelf, args)) == -1)   
        return 0;

    char *b;
    for(b=buffer+len, interpreter[len] = '\0'; b >= buffer ; b--) {
        if (*b == '\n' || *b == '\r' || *b == ' ') 
            *b = '\0';
        interpreter[b - buffer] = *b;
    }

    debug("get_interpreter return(\"%s\"): %s", filename, interpreter); 

    if (*interpreter != '/')
        return 0;

    return 1;
}

LOCAL int
fakechroot_set_interpreter(char *interpreter, char *filename)
{
    debug("set_interpreter(\"%s\", \"%s\")", interpreter, filename); 

    if (! patch_patchelf)
        return 0;

    char *args[] = { patch_patchelf, set_interpreter, interpreter, filename, NULL };
    if (fakechroot_execute(0, patch_patchelf, args) == -1)   
        return 0;
   
    return 1;
}

LOCAL int
fakechroot_count_char(char *buffer, char ch, int buffer_len)
{
    char *b;
    int count = 0;
    for(b = buffer; b < buffer + buffer_len; b++)
        if (*b == ch) count++;
    return count;
}

int
fakechroot_spatch_elf(char *filename)
{
    char interpreter[PATH_MAX];
    char new_interpreter[PATH_MAX];
    int interpreter_len = 0;

    debug("standard patchelf");

    if (patch_init != 2) {
        if (patch_init == 1) {
            int try;
            for (try=10; patch_init == 1 && try; try--) usleep(1000);
        }
        if (patch_init != 2) {
            fakechroot_patch_init();
        }
    }

    if (patch_patchelf && patch_elfloader && filename) {

        if (! fakechroot_get_interpreter(interpreter, filename))
            return 1;

        if (*interpreter != '/')
            return 1;

        if (*patch_elfloader == '/') {

            if (! strcmp(interpreter, patch_elfloader))
                return 1; /* equal no need to patch */

            strlcpy(new_interpreter, patch_elfloader, PATH_MAX);   
        } 
        else { /* env FAKECHROOT_PATCH_ELFLOADER has relative path */

            interpreter_len = strlen(interpreter);

            if (! strncmp(interpreter, patch_base, patch_base_len))
                return 1;      /* already patched */

            char path_interpreter[PATH_MAX];
            sprintf(path_interpreter, "%s/%s", patch_base, interpreter);

            if ((next_realpath(path_interpreter, new_interpreter)) == NULL)
                return 0;

        }
        return fakechroot_set_interpreter(new_interpreter, filename);
    }
    return 1;
}

int
fakechroot_upatch_elf(const char *filename)
{
    debug("patchelf %s", filename);

    if (patch_init != 2) {
        if (patch_init == 1) {
            int try;
            for (try=10; patch_init == 1 && try; try--) usleep(1000);
        }
        if (patch_init != 2) {
            fakechroot_patch_init();
        }
    }

    if (patch_patchelf && patch_elfloader && filename) {

        if (patch_last_time) {
            struct stat fattr;
            if (next_stat(filename, &fattr) == -1 || fattr.st_mtime < patch_last_time) {
                return 0; 
            }
        }
	/*
        char *args[] = { patch_patchelf, set_root_prefix, patch_base, (char *) filename, NULL };
        */
        char *args[] = { patch_patchelf, quiet_mode, set_root_prefix, patch_base, (char *) filename, NULL };
        if (fakechroot_execute(0, patch_patchelf, args) == -1) return 0;
   
        return 1;
    }
    return 1;
}

/* Init the list of sharable libraries open for writing */
void
fakechroot_iniwlib(void)
{
    int i;
    for (i = 0; i < MAPWLIB_SIZE; i++) {    
        map_wlibfd_list[i] = -1;
        map_wlibnam_list[i] = 0;
    }
}

/* Add to the list of sharable libraries open for writing */
int
fakechroot_addwlib(const int fd, char * wlibnam)
{
    int i, match;
    int free_pos = -1;
    char *newnam, *soext_start, *soext_end;

    /* init */
    if (patch_init != 2) {
        if (patch_init == 1) {
            int try;
            for (try=10; patch_init == 1 && try; try--) usleep(1000);
        }
        if (patch_init != 2) {
            fakechroot_patch_init();
        }
    }

    /* get name of file from fd using the symlink /proc/self/fd/NNN */
    if (! wlibnam) {
        char fdnam[30];
        int wliblen;

        wlibnam = alloca(FAKECHROOT_PATH_MAX);
        snprintf(fdnam, sizeof(fdnam), "/proc/self/fd/%d", fd); 
        if ((wliblen = next_readlink(fdnam, wlibnam, FAKECHROOT_PATH_MAX)) == -1)
            return 2;
        if (wliblen == FAKECHROOT_PATH_MAX)
            return 2;
    }
 
    /* look for .so extension */
    match = 0;
    if (soext_start = strstr(wlibnam, ".so")) {
        soext_end = soext_start + 3;
        if (*soext_end == '\0' || *soext_end == '.') {
            debug("fakechroot_addwlib found lib %d -> %s", fd, wlibnam);
            match = 1;
        }
    }
    if (! match)
        return 2;

    /* find empty slot in map_wlibfd_list */
    for (i = 0; i < MAPWLIB_SIZE; i++) {    
        if (map_wlibfd_list[i] == -1) {
            map_wlibfd_list[i] = fd;
            if (i > map_wlib_max) 
                map_wlib_max = i;
            free_pos = i;
            if (map_wlibfd_list[i] == fd)
                break;
            free_pos = -1;
        }
    }
    if (free_pos == -1)
        return 0;
    debug("fakechroot_addwlib free slot (%d) %d -> %s", i, fd, wlibnam);

    /* allocate memory for map_wlibfd_list entry if needed */
    if (map_wlibnam_list[free_pos] == 0) {
        if (newnam = malloc(FAKECHROOT_PATH_MAX)) {
            *newnam = '\0';
            map_wlibnam_list[free_pos] = newnam;
        }
        else {
            return 0;
        }

        if (map_wlibnam_list[free_pos] != newnam) {
            free(newnam);
            return 0;
        }
    } 
    debug("fakechroot_addwlib copy buff (%d) %d -> %s", i, fd, wlibnam);

    /* copy filename to map_wlibfd_list entry */
    strlcpy(newnam, wlibnam, FAKECHROOT_PATH_MAX);
    return 1;
}

/* Is it in the list of sharable libraries open for writing */
int
fakechroot_iswlib(const int fd, char ** wlibnam)
{
    int i, last_open=-1;
    debug("fakechroot_iswlib max %d", map_wlib_max);
    for (i = 0; i <= map_wlib_max; i++) {    
/*
        debug("fakechroot_iswlib (%d) fd %d -> %s", i, fd, map_wlibnam_list[i]);
*/
        if (map_wlibfd_list[i] == fd) {
            if (map_wlibnam_list[i] && *map_wlibnam_list[i] != '\0') {
                if (*wlibnam == 0)
                    *wlibnam = malloc(FAKECHROOT_PATH_MAX);
                if (*wlibnam) {
                    strlcpy(*wlibnam, map_wlibnam_list[i], FAKECHROOT_PATH_MAX);
                    *map_wlibnam_list[i] = '\0';
                    map_wlibfd_list[i] = -1;
                    debug("fakechroot_iswlib found %s", *wlibnam);
                    return 1;
                }
            }
            debug("fakechroot_iswlib error (%d) fd %d", i, fd);
            *map_wlibnam_list[i] = '\0';
            map_wlibfd_list[i] = -1;
            return 0;
        }
    }
    return 0; 
}



#ifdef STANDALONE
int
main(int argc, char *argv[]) {
    char interpreter[PATH_MAX];

    /*
    fakechroot_get_interpreter(interpreter, "/usr/bin/true");
    printf("%s\n", interpreter);

    strcpy(interpreter, "/lib64/ld-2.17.so"); 
    fakechroot_set_interpreter(interpreter, "/usr/bin/true");

    fakechroot_get_interpreter(interpreter, "/usr/bin/true");
    printf("%s\n", interpreter);
    */

    fakechroot_upatch_elf("/tmp/x");
    fakechroot_get_interpreter(interpreter, "/tmp/x");
    printf("%s\n", interpreter);
}
#endif

#define main sentinel_main
#include "sentinel.c"
#undef main
#include <assert.h>
#include <sys/wait.h>

static host_entry *lookup(host_entry **table, const char *path) {
    host_entry *e;
    for(e=table[host_hash(path)];e;e=e->next) if(!strcmp(e->path,path)) return e;
    return NULL;
}
static void put(const char *path) {
    FILE *f=fopen(path,"w"); assert(f); fputs("test",f); assert(!fclose(f));
}
static int logged(const char *needle) {
    char line[16384]; FILE *f=fopen(LOG_FILE,"r"); int found=0;
    assert(f); while(fgets(line,sizeof(line),f)) if(strstr(line,needle)) found=1;
    fclose(f); return found;
}
int main(void) {
    char root[]="./.host-test-XXXXXX", path[PATH_MAX], a[PATH_MAX], b[PATH_MAX];
    struct stat st={0};
    pid_t child;
    assert(mkdtemp(root));
    snprintf(path,sizeof(path),"%s/runtime",root); assert(!mkdir(path,0700));
    snprintf(LOG_FILE,sizeof(LOG_FILE),"%s/runtime/events.log",root);
    host_generation=1;
    /* Full paths, no fixed file ceiling, nanosecond and ownership changes. */
    for(int i=0;i<5000;i++) {
        snprintf(path,sizeof(path),"/test/%d/same.py",i);
        host_record(host_files,path,&st,NULL);
    }
    assert(lookup(host_files,"/test/4999/same.py"));
    assert(lookup(host_files,"/test/0/same.py"));
    host_baseline=1;
    st.st_mtim.tv_nsec=12;
    host_record(host_files,"/test/0/same.py",&st,NULL);
    assert(logged("HOST_FILE_CHANGED /test/0/same.py"));
    host_generation++;
    host_finish(host_files,0);
    assert(lookup(host_files,"/test/0/same.py")); /* incomplete scan keeps entries */
    host_finish(host_files,1);
    assert(!lookup(host_files,"/test/0/same.py"));
    /* Recursive hidden paths, same names, physical symlinks, deletions. */
    snprintf(path,sizeof(path),"%s/.hidden",root); assert(!mkdir(path,0700));
    snprintf(a,sizeof(a),"%s/.hidden/same.py",root); put(a);
    snprintf(b,sizeof(b),"%s/same.py",root); put(b);
    snprintf(path,sizeof(path),"%s/cycle",root); assert(!symlink(".",path));
    host_generation++; host_walk(root,0); host_finish(host_files,1);
    assert(lookup(host_files,a)); assert(lookup(host_files,b));
    assert(lookup(host_files,path));
    assert(logged("HOST_FILE_CREATED"));
    assert(!unlink(a));
    host_generation++; host_walk(root,0); host_finish(host_files,1);
    assert(!lookup(host_files,a)); assert(lookup(host_files,b));
    assert(logged("HOST_FILE_REMOVED"));
    /* PID reuse and exec replacement are distinct identities. */
    host_record(host_processes,"999999",NULL,"pid=999999 start=1 exe=/bin/a");
    host_record(host_processes,"999999",NULL,"pid=999999 start=2 exe=/bin/b");
    assert(logged("HOST_PROCESS_CHANGED 999999"));
    host_generation++; host_scan_processes();
    child=fork(); assert(child>=0);
    if(!child) { sleep(20); _exit(0); }
    host_generation++; host_scan_processes();
    snprintf(path,sizeof(path),"%ld",(long)child);
    assert(lookup(host_processes,path));
    assert(!kill(child,SIGTERM)); assert(waitpid(child,NULL,0)==child);
    host_generation++; host_scan_processes();
    assert(!lookup(host_processes,path));
    assert(host_excluded("/proc/1"));
    assert(host_excluded("/sys/kernel"));
    assert(!host_excluded("/dev/shm/file"));
    assert(!host_excluded("/home/anyone/.hidden"));
    host_event("ESCAPE_TEST","bad\nname");
    assert(logged("ESCAPE_TEST bad\\x0aname"));
    host_baseline=0; host_generation++;
    host_finish(host_files,1);host_finish(host_processes,1);
    printf("PASS: full paths, 5000 entries, metadata, recursive/hidden files, symlinks, deletion, coverage gaps, PID reuse, process start/exit, log escaping. Fixtures: %s\n",root);
    return 0;
}


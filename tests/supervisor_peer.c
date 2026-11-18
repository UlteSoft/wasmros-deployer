/* Hostile, test-only native VM substitute. Never installed with the deployer. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/mempolicy.h>
#include <pthread.h>
#include <unistd.h>

static void *thread_probe(void *value) { return value; }

static int blocked_supervisor(char **argv) {
    int channel[2];if(pipe2(channel,O_CLOEXEC)<0||fcntl(channel[1],F_SETPIPE_SZ,4096)<0)return 82;
    pid_t manager=fork();if(manager<0)return 83;
    if(manager==0){dup2(channel[1],1);close(channel[0]);close(channel[1]);execv(argv[0],argv);_exit(84);}
    close(channel[1]);fcntl(channel[0],F_SETFL,O_NONBLOCK);
    char text[32768]={0};size_t used=0;unsigned loops=0;int status=0;
    while(!strstr(text,"started with PID")){
        ssize_t n=read(channel[0],text+used,sizeof text-1-used);
        if(n>0)used+=(size_t)n;
        if(++loops>1000 || used==sizeof text-1 || waitpid(manager,&status,WNOHANG)==manager){kill(manager,SIGKILL);waitpid(manager,NULL,0);fwrite(text,1,used,stderr);return 85;}
        usleep(5000);
    }
    // Keep the reader open but stop consuming. The child's audit writer blocks,
    // while its supervision thread must still respond to an operator stop.
    usleep(200000);kill(manager,SIGTERM);
    for(loops=0;loops<1000;++loops){
        if(waitpid(manager,&status,WNOHANG)==manager){close(channel[0]);return WIFEXITED(status)&&WEXITSTATUS(status)==1?0:86;}
        usleep(5000);
    }
    kill(manager,SIGKILL);waitpid(manager,NULL,0);close(channel[0]);return 87;
}

int main(int argc,char **argv) {
    if(argc>2&&!strcmp(argv[1],"--blocked-supervisor"))return blocked_supervisor(argv+2);
    setvbuf(stdout,NULL,_IONBF,0);
    if(argc<3 || getuid()==0 || getgid()==0 || prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1) return 71;
    errno=0;int ownership=open("/run/wros-ownership",O_RDONLY|O_DIRECTORY);
    if(ownership>=0||errno!=EACCES)return 102;
    if(prctl(PR_GET_SECCOMP,0,0,0,0)!=2)return 95;
    errno=0;if(unshare(0)!=-1||errno!=EPERM)return 96;
    errno=0;if(setns(-1,0)!=-1||errno!=EPERM)return 97;
    errno=0;if(syscall(SYS_clone3,NULL,0)!=-1||errno!=ENOSYS)return 98;
    errno=0;long cloned=syscall(SYS_clone,CLONE_NEWUSER|SIGCHLD,NULL,NULL,NULL,0);
    if(cloned==0)_exit(99);
    if(cloned!=-1||errno!=EPERM)return 100;
    pthread_t thread;void *result=NULL;
    if(pthread_create(&thread,NULL,thread_probe,&result)!=0||pthread_join(thread,&result)!=0||result!=&result)return 101;
    char bytes[512]={0};
    int f=open("/proc/self/cgroup",O_RDONLY);if(f<0)return 72;
    ssize_t n=read(f,bytes,sizeof bytes-1);close(f);
    if(n<0 || strcmp(bytes,"0::/\n")) return 73;
    f=open(argv[argc-1],O_RDONLY);if(f<0)return 93;
    struct stat image;unsigned char magic[4];
    if(fstat(f,&image)!=0 || image.st_uid!=getuid() || image.st_gid!=getgid() ||
       (image.st_mode&0777)!=0400 || read(f,magic,sizeof magic)!=sizeof magic ||
       memcmp(magic,"\0asm",sizeof magic))return 94;
    close(f);
    f=open(argv[argc-1],O_WRONLY);
    if(f<0){if(errno!=EROFS)return 74;}
    else{errno=0;n=write(f,"X",1);close(f);if(n!=-1 || errno!=EPERM)return 75;}
    printf("PEER confined uid=%u gid=%u sealed=1 namespace-pinned=1 pthread=1\n",getuid(),getgid());
    const char *mode=argv[2];
    if(!strcmp(mode,"placement")||!strcmp(mode,"placementcrash")){
        cpu_set_t set;CPU_ZERO(&set);
        if(sched_getaffinity(0,sizeof set,&set)<0||CPU_COUNT(&set)!=1||!CPU_ISSET(1,&set))return 88;
        CPU_ZERO(&set);CPU_SET(0,&set);errno=0;
        if(sched_setaffinity(0,sizeof set,&set)!=-1||errno!=EINVAL)return 89;
        unsigned long outside=1;errno=0;
        if(syscall(SYS_set_mempolicy,MPOL_BIND,&outside,8*sizeof outside)!=-1||errno!=EINVAL)return 90;
        unsigned char *page=malloc(4096);if(!page)return 91;
        page[0]=0x5a;__asm__ volatile(""::"r"(page):"memory");
        int node=-1;
        if(syscall(SYS_get_mempolicy,&node,NULL,0,page,MPOL_F_NODE|MPOL_F_ADDR)!=0||node!=1)return 92;
        free(page);puts("PEER placement cpu=1 mems=1 page-node=1");
        if(!strcmp(mode,"placementcrash"))raise(SIGSEGV);
        return 0;
    }
    if(!strcmp(mode,"normal"))return 0;
    if(!strcmp(mode,"crash")) {raise(SIGSEGV);return 76;}
    if(!strcmp(mode,"memory")){
        for(;;){unsigned char *p=malloc(4*1024*1024);if(!p)return 77;memset(p,0x5a,4*1024*1024);__asm__ volatile(""::"r"(p):"memory");}
    }
    if(!strcmp(mode,"orphan") || !strcmp(mode,"stop")){
        pid_t child=fork();if(child<0)return 78;
        if(child==0){setsid();signal(SIGTERM,SIG_IGN);printf("PEER orphan pid=%d\n",getpid());for(;;)pause();}
        if(!strcmp(mode,"orphan"))return 0;
        signal(SIGTERM,SIG_IGN);for(;;)pause();
    }
    if(!strcmp(mode,"pids")){
        unsigned children=0;
        for(unsigned i=0;i<64;++i){pid_t child=fork();if(child<0){printf("PEER task limit after %u children errno=%d\n",children,errno);return errno==EAGAIN?0:79;}if(child==0)for(;;)pause();++children;}
        return 80;
    }
    if(!strcmp(mode,"flood")||!strcmp(mode,"floodstop")){
        for(unsigned i=0;i<100000;++i)puts("bounded diagnostic output");
        if(!strcmp(mode,"flood"))return 0;
        signal(SIGTERM,SIG_IGN);for(;;)pause();
    }
    if(!strcmp(mode,"parentdeath")){for(;;)pause();}
    return 81;
}

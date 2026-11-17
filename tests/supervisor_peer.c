/* Hostile, test-only native VM substitute. Never installed with the deployer. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

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
    char bytes[512]={0};
    int f=open("/proc/self/cgroup",O_RDONLY);if(f<0)return 72;
    ssize_t n=read(f,bytes,sizeof bytes-1);close(f);
    if(n<0 || strcmp(bytes,"0::/\n")) return 73;
    f=open(argv[argc-1],O_WRONLY);
    if(f<0){if(errno!=EROFS)return 74;}
    else{errno=0;n=write(f,"X",1);close(f);if(n!=-1 || errno!=EPERM)return 75;}
    printf("PEER confined uid=%u gid=%u sealed=1\n",getuid(),getgid());
    const char *mode=argv[2];
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

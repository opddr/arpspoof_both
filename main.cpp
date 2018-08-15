#include "spooftool.h"

using namespace std;

void *Thread(void *p)
{
    spooftool *Object = (spooftool *)p;
    Object->keep_spoofing();
}

int main(int argc,char **argv)
{
    pthread_t pt_host1,pt_host2;
    int *test;
    printf("what");
    if(argc != 4)
    {
        printf("USAGE : <interface> <sender ip> <receiver ip>");
        exit(1);
    }
    spooftool host1(argv[1],argv[2],argv[3]);
    spooftool host2(argv[1],argv[3],argv[2]);
    pthread_create(&pt_host1,NULL,Thread,&host1);
    pthread_create(&pt_host2,NULL,Thread,&host2);
    printf("thread");
    pthread_join(pt_host1,NULL);
    pthread_join(pt_host2,NULL);
    return 0;
}

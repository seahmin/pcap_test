#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    int res;
    char *dev="eth0";			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program *fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression THIS ONE ONLY CATCHES PORT HTTP*/
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return(2);
    }
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);

    //while((
    if(res=pcap_next_ex(handle, &header, &packet)==1){
       // if(res==0) continue;
        printf("Source MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", *(packet+6), *(packet+7), *(packet+8), *(packet+9), *(packet+10), *(packet+11));
        printf("Destination MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", *(packet), *(packet+1), *(packet+2), *(packet+3), *(packet+4), *(packet+5));
        if(packet[12]==0x08 && packet[13]==0x00){
            printf("Source IP Address : %d.%d.%d.%d\n", *(packet+26), *(packet+27), *(packet+28), *(packet+29));
            printf("Destination IP Address : %d.%d.%d.%d\n", *(packet+30), *(packet+31), *(packet+32), *(packet+33));
        }

    }
    pcap_close(handle);
    return 0;
}

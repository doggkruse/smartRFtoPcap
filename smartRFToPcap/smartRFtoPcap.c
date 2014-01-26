//
//  main.c
//  smartRFtoPcap
//
//  Created by Geoffrey Kruse on 1/25/14.

/////////////////////////////////////////////////////////////////////////////
//This is free and unencumbered software released into the public domain.
//
//Anyone is free to copy, modify, publish, use, compile, sell, or
//distribute this software, either in source code form or as a compiled
//binary, for any purpose, commercial or non-commercial, and by any
//means.
//
//In jurisdictions that recognize copyright laws, the author or authors
//of this software dedicate any and all copyright interest in the
//software to the public domain. We make this dedication for the benefit
//of the public at large and to the detriment of our heirs and
//successors. We intend this dedication to be an overt act of
//relinquishment in perpetuity of all present and future rights to this
//software under copyright law.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
//OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
//ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
//OTHER DEALINGS IN THE SOFTWARE.
/////////////////////////////////////////////////////////////////////////////

#include <err.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

pcap_t *pcap_dumpfile;
pcap_dumper_t *dumper;
FILE * inFile;

#pragma pack(1)
typedef struct
{
    uint8_t  packetInfo;
    uint32_t packetNumber;
    uint64_t timeStamp;
    uint16_t payloadLength;
    uint8_t  packetLen;
    uint8_t  packet[255];
}psdPacketCaptureType;
#pragma pack()

psdPacketCaptureType packetData;

#define OUT_FILENAME "out-dump.pcap"
#define IN_FILENAME  "input.psd"
#define MICROSECONDS_PER_SEC 1000000

int main(int argc, const char * argv[])
{
    size_t bytesRead;
    struct pcap_pkthdr pcapHdr;
    struct timeval ts;
    
    pcap_dumpfile = pcap_open_dead(DLT_USER0, 128);
    if(pcap_dumpfile == NULL)
    {
        err(1, "pcap_open_dead: ");
    }
    dumper = pcap_dump_open(pcap_dumpfile, OUT_FILENAME);
    pcap_dump_flush(dumper);
    if (dumper == NULL)
    {
        warn("pcap_dump_open");
        pcap_close(pcap_dumpfile);
        exit(1);
    }
    
    //open the psd file
    inFile = fopen(IN_FILENAME, "r");
    
    if(NULL == inFile)
    {
        printf("Error opening psd file\n");
        exit(1);
    }
    
    do
    {
        bytesRead = fread(&packetData, 1, sizeof(psdPacketCaptureType), inFile);
        
        printf("Packet: %u len: %u\n",packetData.packetNumber, packetData.packetLen - 2);
        
        if(bytesRead)
        {
            // TI says the timestamp is in microseconds, they lie
            packetData.timeStamp /= 100;
            // capture timestamp is in microseconds
            ts.tv_sec = (packetData.timeStamp / (uint64_t)MICROSECONDS_PER_SEC);
            ts.tv_usec = (packetData.timeStamp % (uint64_t)MICROSECONDS_PER_SEC);
            pcapHdr.ts = ts;
            
            // last 2 bytes of payload are not part of the BLE packet
            pcapHdr.caplen = pcapHdr.len = packetData.packetLen - 2;
            
            pcap_dump((unsigned char *)dumper, &pcapHdr, packetData.packet);
            pcap_dump_flush(dumper);
        }
    }while(bytesRead > 0);
    
    return 0;
}


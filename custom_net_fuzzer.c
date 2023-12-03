/*
custom_net_fuzzer - a shared DLL to enable network fuzzing in winAFL
-------------------------------------------------------------

Written and maintained by Maksim Shudrak <mxmssh@gmail.com>

Copyright 2018 Salesforce Inc. All Rights Reserved.

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

#include "custom_winafl_server.h"

static u8  enable_socket_fuzzing = 0; /* Enable network fuzzing           */
static u32 target_port = 1801;         /* Target port to send test cases   */
static u32 socket_init_delay = SOCKET_INIT_DELAY; /* Socket init delay    */
static char *target_ip_address = "127.0.0.1";  /* Target IP to send test cases     */


static SOCKET ListenSocket = INVALID_SOCKET;
static SOCKET ClientSocket = INVALID_SOCKET;

// typedef struct  {
//     char * buf;
//     int buf_len;
//     int first_time;
// }DataFuzz ,*DataFuzzp;

static void send_data_tcp(const char *buf, const int buf_len, int first_time) {
    static struct sockaddr_in si_other;
    static int slen = sizeof(si_other);
    static WSADATA wsa;
    int s;
    if(first_time == 0x0) {
        
        Sleep(300);
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            FATAL("WSAStartup failed. Error Code : %d", WSAGetLastError());
        // setup address structure
    }
    memset((char *)&si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(target_port);
    si_other.sin_addr.S_un.S_addr = inet_addr((char *)target_ip_address);
    // fprintf(stderr, "firs_time is %d\n", first_time);
        
        
    /* In case of TCP we need to open a socket each time we want to establish
    * connection. In theory we can keep connections always open but it might
    * cause our target behave differently (probably there are a bunch of
    * applications where we should apply such scheme to trigger interesting
    * behavior).
    */
    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == SOCKET_ERROR)
        FATAL("socket() failed with error code : %d", WSAGetLastError());

    // Connect to server.
    if (connect(s, (SOCKADDR *)& si_other, slen) == SOCKET_ERROR) return 0;
        //FATAL("connect() failed with error code : %d", WSAGetLastError());
    // Send our buffer
    if (send(s, buf, buf_len, 0) == SOCKET_ERROR) return 0;
        //FATAL("send() failed with error code : %d", WSAGetLastError());
    fprintf(stderr, "send success!!%d\n", first_time);
    int recvTimeout = 100;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&recvTimeout ,sizeof(int));
    char recData[1024];
    if (recv(s, recData, 1024, 0)==SOCKET_ERROR){
        fprintf(stderr, "recv error!!%d\n", first_time);
    }else {
        fprintf(stderr, "recv success!!%d\n", first_time);
    }
    // Sleep(100);
    // shutdown the connection since no more data will be sent
    if (shutdown(s, 0x1/*SD_SEND*/) == SOCKET_ERROR)
        FATAL("shutdown failed with error: %d\n", WSAGetLastError());
    // close the socket to avoid consuming much resources
    if (closesocket(s) == SOCKET_ERROR)
        FATAL("closesocket failed with error: %d\n", WSAGetLastError());
}



CUSTOM_SERVER_API int APIENTRY dll_run(char *data, long size, int fuzz_iterations) {
    send_data_tcp(data, size, fuzz_iterations);
    return 1;
}


CUSTOM_SERVER_API int APIENTRY dll_init() {
    
    return 1;
}


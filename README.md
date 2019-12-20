# LazyPixie: an arbitrary write kernel exploit in PXI buffer descriptor handling code

*Responsibly disclosed. Fixed by Nintendo in system update 11.12.0-44.*

## Introduction

A few months ago, I decided to resume reverse-engineering work on the 3DS kernel, in particular the aspects nobody really publically, thoroughsly reversed and/or documented.

One such aspect is the IPC (inter-process communication) marshalling for buffers eventually passed to Process9.

For those unfamiliar with the 3DS hardware and software architecture, here is a quick recap:

* The 3DS has two main processors: one Arm11 MPCORE (2 or 4 cores), running the main system, games, etc. and an Arm9TDMI, handling storage device accesses and security tasks
* Both processors run the same OS, Horizon OS. The kernel is a microkernel and drivers are implemented in userland (in "sysmodules")
    * Each Arm11 process has a fine-grained system call whitelist, service access list and MMIO access list
        * Games and other application have the least privileges
        * "Services" have more privileges, obviously including the ability to respond to service requests
    * The Arm9 runs a trimmed down version of the OS. There's only one userland process running on the Arm9, called `Process9` -- which is allowed to execute supervisor-mode code!
* Both processors communicate with each other through the `PXI` MMIO registers (which is basically two FIFOs)
    * The Arm11 `pxi` sysmodule (which is also a driver) communicates with `Process9` this way. It forwards all the IPC requests and replies it receives as they are

The things is, however, that the two processors **are not cache-coherent with each other**. In fact, the good old **Arm9 doesn't even have a MMU to begin with**!

This means it's up to the Arm11 kernel to expose buffers coming from userland Arm11 processes as chunks of physical memory with their respecting sizes; the Arm11 kernel has to ensure cache coherency as well (via clean and/or invalidate cache operations).

This is achieved by Arm11 drivers sending a special IPC buffer descriptor type. I'll refer to it as "PXI IPC buffer descriptor" or even just "PXI descriptor".

PXI descriptors require the destination Arm11 process to set up page-aligned buffers where the "physical address" and "size" metadata pairs will be written to by the Arm11 kernel. I'll refer to such metadata buffers as "static buffers".

This particular type of buffer descriptor is **only used when sending commands to the `pxi` sysmodule** (which then forwards them to `Process9`) and by `Process9` on a reply. This means the kernel code handling has most likely been much less tested and reviewed than more common descriptor types, and is more prone to having bugs.

It happened that the code handling PXI buffer descriptors in a request (not a reply) **did indeed have critical security flaws**!

## Exploitation requirements

Be on a version lower than 11.12.0-44, and have at least one of the following:

* Code execution in *any* Arm11 service
* Unprivileged code execution AND being able to write to the `TLS/*(thread local storage)*/+0x180` region of a thread receiving and handling service commands

## Description of the flaw

The Arm11 kernel code handling PXI IPC buffer descriptors (e.g. those of the form `(sz <<14) | (id << 4) | (read_only << 1) | 4)` has multiple flaws.

The flaws are located in cases 2 and 3 of the function handling IPC parameter translation (function address: `0xFFF23824` on the kernel image that comes with the retail `11.11.0-43E N3DS` update).

The destination "static buffer" address is only checked for page-alignment. **It is possible to pass any arbitrary page-aligned address, included kernel-space addresses**.

The size of the static buffer is mostly disregarded, as long as it doesn't exceed 0x1000 bytes. In fact, **it is possible to pass a 0 size to avoid a data abort in `cleanDataCacheRange` following an erroneous translation**.

The below commented kernel pseudocode should highlight these vulnerabities in a clear enough way.

### Kernel pseudocode

```cpp
/* IPC descriptor parsing and some sanity checks over "static buffer index" & add buffer descriptor to dst process TLS, irrelevant. */
v47 = dstStaticBufArea[2 * staticbufIndex];

staticBufAddrPxi = dstStaticBufArea[2 * staticbufIndex + 1];
staticBufSize = v47 >> 14;

/* Check if the destination (service/server-side) buffer is aligned to 0x1000 bytes. */
if (staticBufAddrPxi << 20)
    kernelpanic();

/* Check if the destination (service/server-side) buffer doesn't exceed 0x1000 bytes. */
if (staticBufSize > 0x1000)
    kernelpanic();

/* ... **SOURCE** buffer permission checks, between srcBuffer and srcBuffer+srcBufferSize ... */

dstProcess->LockProcessAddressSpaceMutex();

/* UNCHECKED ATTACKER-CONTROLLED ADDRESSS! Flaw (1) */
u32 *staticBufPxi = (u32 *)staticBufAddrPxi;

u32 i = 0;
bool bigChunkEncountered = false;
Result res = 0;
for (auto it : MakePhysicalViewOfUserBuffer(srcBuffer, srcBuffer+srcBufferSize)) {
    bigChunkEncountered = bigChunkEncountered || it->chunkSize() >= 0x4000;

    /* Some other checks that we pass anyway... */
    if (i >= 512) {
        res = 0xC8A01836;
        break;
    }
    staticBufPxi[i++] = it->chunkPhysAddr();
    staticBufPxi[i++] = it->chunkSize();

    /* Clean&invalidate cache over the source buffer chunk */
    if (it->chunkSize() < 0x4000)
        cleanInvalidateDataCacheRange(PA2KERNELVA(it->chunkPhysAddr), it->chunkSize());
}

if (srcBufferSize == 0) {
    res = 0xE0E01BF5;
} else if (bigChunkEncountered) {
    cleanInvalidateEntireDataCache();
}

/* Some other checks that we always pass anyway... */

if (res != 0xC8A01836) {
    if (res < 0)
        kernelpanic();
    uintptr_t kernelStaticBufVa = convertVaToPa(dstProcess->ttbr1, staticBufPxi);
    cleanDataCacheRange(PA2KERNELVA(kernelStaticBufVa), staticBufSize);

    /* Write descriptor to dst process cmdbuf... */
    /* Register static buffer into global structure... */
}
```

## Exploitation steps

We know that:

* we can write to any page-aligned address, passed as the static buffer's address
the data written to that address is in the format `{physical address, size}`, and the address misalignement (lower 12 bits) is preserved in the first chunk metadata by definition
* we can set the static buffer size to 0 in the descriptor, to avoid a data abort in `cleanDataCacheRange` following an erroneous translation
* additionally, we can exploit the flaw multiple times in a single IPC request, by using exposing and using multiple "PXI" static buffers at once.

This is easily exploitable:

* where to write: to translation tables (through the FCRAM linear kernel mapping), in particular to the unused entry mapping 1MB at `0x80000000`
* how: by passing a source page-aligned buffer `bitwise OR` 1. With this, the kernel writes `PA(buffer | 1) = PA(buffer) | 1` to the entry, and this corresponds to a valid entry mapping a L2 page table

The end result is that we're now able to control a L2 table affecting the kernel address space, and thus map kernel memory with arbitrary permissions at will.

## Fix

Nintendo fixed the flaw in system update **11.12.0-44** by doing the following:

* requiring PXI static buffers to be exactly 0x1000 bytes in size
* properly checking that the entirety of the static buffer is writable in usermode by the destination process

## Proof of Concept code

A small PoC is included in the `poc` subfolder. Luma3DS is required to run the built binary, `poc.3dsx`, as the PoC requires access to the `ReplyAndReceive` system call to run.

The code of the PoC is in `source/main.c`. In around 70 lines, the PoC uses the exploit to remap the AXIWRAM to address 0x80000000, with the mapping being fully accessible (RWX) to userland. While this is not done in the PoC, it is obviously possible to rewrite kernel code and data using this mapping.
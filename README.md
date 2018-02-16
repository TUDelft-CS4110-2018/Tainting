# Tainting

In order to practice tainting, we are going to follow the proof of concept form Jonathan Salwan: http://shell-storm.org/blog/Taint-analysis-and-pattern-matching-with-Pin/

In this example, we will use Intel Pin, or Pintool: https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool

Tainting is the process of logging where read input data could possibly end up when running software. You do this by keeping track of the memory addresses that are used to store the input data. Initially, this is easy because we exactly know the memory address that is provided to a system call that is used to read the data. We capture such calls using an instrumentation framework such as Pin.

As an example, I move to the ManualExamples directory that comes with Pin (pin-3.5-97503-gac534ca30-clang-mac/source/tools/ManualExamples/) and create the small executable test1.cpp, from the instructions by Jonathan Salwan:

```c
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void foo(char *buf)
{
  char a;
  a = buf[0];
  a = buf[4];
  a = buf[8];
  buf[5]  = 't';
  buf[10] = 'e';
  buf[20] = 's';
  buf[30] = 't';
}

int main(int ac, char **av)
{
  int fd;
  char *buf;

  if (!(buf = (char*) malloc(32)))
    return -1;

  fd = open("./file.txt", O_RDONLY);
  read(fd, buf, 32), close(fd);
  foo(buf);
}
```

which I compile using g++

```
g++ test1.cpp
```

running

```
../../../pin -t obj-intel64/strace.dylib -- ./a.out
```

then provides me with a list of all system calls made by the executable:

```
cat strace.out
...
0x7fff8b372ec8: 16777232(0x407, 0x1, 0x7fff738c5678, 0x8, 0x6834365f363878, 0x0)returns: 0x0
0x7fff8b372f04: 16777237(0x407, 0xe03, 0xe03, 0x14, 0x6834365f363878, 0x0)returns: 0x0
0x7fff8b372f70: 16777247(0x7fff5ae3bae0, 0x3, 0x34, 0x2c, 0x907, 0x0)returns: 0x0
0x7fff5fca75e4: 16777234(0x407, 0x10b, 0x7fff5ae3c050, 0x148, 0x7fff5ae3c020, 0x7fff5ae3c058)returns: 0x0
0x7fff8b372ebc: 16777231(0x407, 0x7fff5ae3d570, 0x100000, 0xfffff, 0x7000001, 0x3)returns: 0x0
0x7fff8b378c00: 33554437(0x104dc2fa0, 0x0, 0x0, 0x84260000, 0x1, 0x20)returns: 0x3
0x7fff8b37a360: 33554435(0x3, 0x7fd842600000, 0x20, 0x84260000, 0x1, 0x20)returns: 0x20
0x7fff8b379838: 33554438(0x3, 0x7fd842600000, 0x0, 0x84260000, 0x1, 0x20)returns: 0x0
```

The numbers 16777232, 33554437, etc. are system call numbers. These will be different on different operating systems. The arguments of the system calls are shown in brackets, as well as the return value. I can get a similar overview by running dtrace, a tracer for Mac OS.

```
sudo dtruss -n a.out
...
13517/0x81060:  stat64("/AppleInternal\0", 0x7FFF54913E18, 0x1)		 = -1 Err#2
13517/0x81060:  csops(0x34CD, 0x7, 0x7FFF54913930)		 = -1 Err#22
13517/0x81060:  sysctl(0x7FFF54913CF0, 0x4, 0x7FFF54913A68)		 = 0 0
13517/0x81060:  csops(0x34CD, 0x7, 0x7FFF54913220)		 = -1 Err#22
13517/0x81060:  proc_info(0x2, 0x34CD, 0x11)		 = 56 0
13517/0x81060:  open("./test.txt\0", 0x0, 0x0)		 = 3 0
13517/0x81060:  read(0x3, "abcdefghijklmnopqrstuvwxyz123456\0", 0x20)		 = 32 0
13517/0x81060:  close(0x3)		 = 0 0
```

The only difference is that dtrace knows the actual system call names instead of numbers, and it knows what the arguments are supposed to mean. It for instance replaces the pointer to 0x7fd842600000 with its content. The first argument to the read call is the file pointer 0x3, which as you can see was the return value of the open call. It is instructive to see how Pin instruments this code (see Jonatha Salwan for an explanation of instrumentation and tainting). strace.cpp contains the following code:

```c
#include <stdio.h>

#if defined(TARGET_MAC)
#include <sys/syscall.h>
#else
#include <syscall.h>
#endif

#include "pin.H"


FILE * trace;


// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
#if defined(TARGET_LINUX) && defined(TARGET_IA32) 
    // On ia32 Linux, there are only 5 registers for passing system call arguments, 
    // but mmap needs 6. For mmap on ia32, the first argument to the system call 
    // is a pointer to an array of the 6 arguments
    if (num == SYS_mmap)
    {
        ADDRINT * mmapArgs = reinterpret_cast<ADDRINT *>(arg0);
        arg0 = mmapArgs[0];
        arg1 = mmapArgs[1];
        arg2 = mmapArgs[2];
        arg3 = mmapArgs[3];
        arg4 = mmapArgs[4];
        arg5 = mmapArgs[5];
    }
#endif

    fprintf(trace,"0x%lx: %ld(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)",
        (unsigned long)ip,
        (long)num,
        (unsigned long)arg0,
        (unsigned long)arg1,
        (unsigned long)arg2,
        (unsigned long)arg3,
        (unsigned long)arg4,
        (unsigned long)arg5);
}

// Print the return value of the system call
VOID SysAfter(ADDRINT ret)
{
    fprintf(trace,"returns: 0x%lx\n", (unsigned long)ret);
    fflush(trace);
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),
        PIN_GetSyscallArgument(ctxt, std, 0),
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    SysAfter(PIN_GetSyscallReturn(ctxt, std));
}

VOID Fini(INT32 code, VOID *v)
{
    fprintf(trace,"#eof\n");
    fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This tool prints a log of system calls" 
                + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    trace = fopen("strace.out", "w");

    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddSyscallExitFunction(SyscallExit, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
```

Most important are the SyscallEntry and SyscallExit functions. Using the PIN_AddSyscallEntryFunction (and similarly Exit), Pin instructs that whenever a sytem call is started and finished, it calls these two functions respectively. All the functions do is print the sys call, its arguments, and its return value. You can do much more fancy things with Pin if you want to, such as modifying the system call that is made, or one of its arguments.

In order to taint this code, we create a file named taint.cpp (from Jonathan Salwan):

```c
#include "pin.H"
#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>

/* bytes range tainted */
struct range
{
  UINT64 start;
  UINT64 end;
};

std::list<struct range> bytesTainted;

INT32 Usage()
{
    cerr << "Ex 1" << endl;
    return -1;
}

VOID ReadMem(UINT64 insAddr, std::string insDis, UINT64 memOp)
{
  list<struct range>::iterator i;
  UINT64 addr = memOp;

  for(i = bytesTainted.begin(); i != bytesTainted.end(); ++i){
      if (addr >= i->start && addr < i->end){
        std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis<< std::endl;
      }
  }
}

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT64 memOp)
{
  list<struct range>::iterator i;
  UINT64 addr = memOp;

  for(i = bytesTainted.begin(); i != bytesTainted.end(); ++i){
      if (addr >= i->start && addr < i->end){
        std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
      }
  }
}

VOID Instruction(INS ins, VOID *v)
{
  if (INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  else if (INS_MemoryOperandIsWritten(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
}
/* Taint from Syscalls */
UINT64 start = 0, size = 0;
bool is_read = false;

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  struct range taint;

  //unsigned int i;
  is_read = false;

  if (PIN_GetSyscallNumber(ctx, std) == 33554435){

      start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
      is_read = false;
      size  = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

      taint.start = start;
      taint.end   = start + size;
      bytesTainted.push_back(taint);
      std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << taint.start << " to 0x" << taint.end << " (via read)"<< std::endl;
      std::cout << "data: " << (char*) start << endl;

      std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start+size << " (via read)"<< std::endl;
  }
}

VOID Syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  struct range taint;

  if (is_read){

      //start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
      size  = static_cast<UINT64>((PIN_GetSyscallReturn(ctx, std)));

      taint.start = start;
      taint.end   = start + size;
      bytesTainted.push_back(taint);
      std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << taint.start << " to 0x" << taint.end << " (via read)"<< std::endl;
      std::cout << "data: " << (char*) start << endl;
  }
}

int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }

    PIN_SetSyntaxIntel();
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    PIN_AddSyscallExitFunction(Syscall_exit, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();

    return 0;
}
```

I only slightly modified this file, such that it runs on my Macbook. For instance, I replaced the read system call number with 33554435, which is the number on my system (something to do with the Mach microkernel, but after a lot of searching, I still haven't figured out completely why these numbers are they way they are....if you know, please tell me!). If you run Linux, you can probably use the code from Salwan.

Try to understand the code. All it does is mark portions of memory that can be influenced by the file input. If there is a read or write instruction to/from this memory, it is printed. The check for read/write instructions is instrumented on every instruction. Hence the code will be considerably slower than running the code without instrumentation. The output I get is:

```
../../../pin -t obj-intel64/taint1.dylib -- ./a.out

[TAINT]			bytes tainted from 0x7fb9b2401ea0 to 0x7fb9b2401ec0 (via read)
data: 
[TAINT]			bytes tainted from 0x7fb9b2401ea0 to 0x7fb9b2401ec0 (via read)
[READ in 7fb9b2401ea0]	10a954e8c: mov al, byte ptr [rdi]
[READ in 7fb9b2401ea4]	10a954e95: mov al, byte ptr [rdi+0x4]
[READ in 7fb9b2401ea8]	10a954e9f: mov al, byte ptr [rdi+0x8]
[WRITE in 7fb9b2401ea5]	10a954ea9: mov byte ptr [rdi+0x5], 0x74
[WRITE in 7fb9b2401eaa]	10a954eb1: mov byte ptr [rdi+0xa], 0x65
[WRITE in 7fb9b2401eb4]	10a954eb9: mov byte ptr [rdi+0x14], 0x73
[WRITE in 7fb9b2401ebe]	10a954ec1: mov byte ptr [rdi+0x1e], 0x74
```

You may also try the more sophisticated (but still proof of concept) tainting code from Salwan. They all work on my system, but I am unsure about their precision. If you want to apply tainting to real code, I suggest to either get Triton running (the tainter did not work on my Mac, and requires an older version of Pin) or search for other existing tainting tools. Because they require low level system access, they can be troublesome to get get running Please let me know if you manage to succesfully download, install, and run a memory tainter! I will post these in this directory.





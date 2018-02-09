# Tainting

In order to practice tainting, we are going to follow the proof of concept form Jonathan Salwan: http://shell-storm.org/blog/Taint-analysis-and-pattern-matching-with-Pin/

In this example, we will use Intel Pin, or Pintool: https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool

Tainting is the process of logging where read input data could possibly end up when running software. You do this by keeping track of the memory addresses that are used to store the input data. Initially, this is easy because we exactly know the memory address that is provided to a system call that is used to read the data. We capture such calls using an instrumentation framework such as Pin.

For example, running 

```
0x7fff8b372ec8: 16777232(0x407, 0x1, 0x7fff738c5678, 0x8, 0x6834365f363878, 0x0)returns: 0x0
0x7fff8b372f04: 16777237(0x407, 0xe03, 0xe03, 0x14, 0x6834365f363878, 0x0)returns: 0x0
0x7fff8b372f70: 16777247(0x7fff5ae3bae0, 0x3, 0x34, 0x2c, 0x907, 0x0)returns: 0x0
0x7fff5fca75e4: 16777234(0x407, 0x10b, 0x7fff5ae3c050, 0x148, 0x7fff5ae3c020, 0x7fff5ae3c058)returns: 0x0
0x7fff8b372ebc: 16777231(0x407, 0x7fff5ae3d570, 0x100000, 0xfffff, 0x7000001, 0x3)returns: 0x0
0x7fff8b378c00: 33554437(0x104dc2fa0, 0x0, 0x0, 0x84260000, 0x1, 0x20)returns: 0x3
0x7fff8b37a360: 33554435(0x3, 0x7fd842600000, 0x20, 0x84260000, 0x1, 0x20)returns: 0x20
0x7fff8b379838: 33554438(0x3, 0x7fd842600000, 0x0, 0x84260000, 0x1, 0x20)returns: 0x0
```

```
13517/0x81060:  stat64("/AppleInternal\0", 0x7FFF54913E18, 0x1)		 = -1 Err#2
13517/0x81060:  csops(0x34CD, 0x7, 0x7FFF54913930)		 = -1 Err#22
13517/0x81060:  sysctl(0x7FFF54913CF0, 0x4, 0x7FFF54913A68)		 = 0 0
13517/0x81060:  csops(0x34CD, 0x7, 0x7FFF54913220)		 = -1 Err#22
13517/0x81060:  proc_info(0x2, 0x34CD, 0x11)		 = 56 0
13517/0x81060:  open("./test.txt\0", 0x0, 0x0)		 = 3 0
13517/0x81060:  read(0x3, "abcdefghijklmnopqrstuvwxyz123456\0", 0x20)		 = 32 0
13517/0x81060:  close(0x3)		 = 0 0
```





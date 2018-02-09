# Tainting

In order to practice tainting, we are going to follow the proof of concept form Jonathan Salwan: http://shell-storm.org/blog/Taint-analysis-and-pattern-matching-with-Pin/

In this example, we will use Intel Pin, or Pintool: https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool

Tainting is the process of logging where read input data could possibly end up when running software. You do this by keeping track of the memory addresses that are used to store the input data. Initially, this is easy because we exactly know the memory address that is provided to a system call that is used to read the data. We capture such calls using an instrumentation framework such as Pin.

For example...




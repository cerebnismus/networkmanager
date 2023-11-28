### networkmanager tools

#### usage
```bash
sudo g++ -std=c++11 *.cpp -I.
sudo ./a.out <interfaceName> <destinationIP>
```

#### todo
- [ ] #define IPOPT_TS  68    /* timestamp */
- [ ] #define IPOPT_RR  7     /* record packet route */
- [ ] checksum validation
- [ ] add cross-plat makefile
- [x] add multithread logic [main.cpp]
- [ ] void to int for return values
- [x] loop for select bpf device [packets_bpf.cpp]
- [x] add timestamp for each packet [packets.cpp]
- [x] print timestamp for each packet [packets_bpf.cpp]
- [ ] pragma features in C/C++ ?
- [ ] 'this' pointer for class methods

- [ ] multicore support
```C++
    // Set CPU affinity for this thread
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
```

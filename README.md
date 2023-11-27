### networkmanager tools

#### usage
```bash
sudo g++ -std=c++11 *.cpp -I.
sudo ./a.out <interfaceName> <destinationIP>
```

#### todo
- [ ] 'this' pointer for class methods
- [ ] void to int for return values
- [ ] fix multithread logic
- [ ] add a cross-plat makefile
- [ ] epoll for linux ?
- [ ] #define IPOPT_RR  7     /* record packet route */
- [ ] #define IPOPT_TS  68    /* timestamp */
- [ ] multicore support
```C++
    // Set CPU affinity for this thread
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
```

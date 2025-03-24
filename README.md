Unix Operating System
=======================

# Features
- Support for C user programs
- Implemented concurrency with processes and threads
- Implemented thread scheduling using the Strict Priority Scheduling Algorithm
    - Includes implementing priority donation and priority inversion to optimize synchronization with threads of differing priority
- Implemented synchronization (locks, semaphores, condition variables, RW locks) on kernel side and user side
- Implemented virtual memory and page tables
- Implemented extensible file system with disk management, page directory based on linux file system- used inodes to represent extensible files as blocks internally
- Optimized file system with buffer cache to cache repeated reads/writes before writing to disk periodically, developed eviction algorithm using the Clock Replacement Algorithm
- Utilized synchronization to make file system concurrency-safe
- Implemented all fundamental system calls for concurrency, file system functionality, and running kernel mechanisms

# Setup

Compiling and running tests requires the installation of docker.

After installation, cd into the `/docker` directory and run `docker-compose up -d`.

SSH into the Container with `ssh workspace@127.0.0.1 -p 16222`. Use the password `workspace`.

To run the tests (examples of C programs that use the features described in the previous section), cd into the specific folder (`src/userprog` or `src/threads` or `src/filesys`), and run `make` then `make check`.
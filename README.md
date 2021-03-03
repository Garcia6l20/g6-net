# G6 network library

## Clone the project

```bash
git clone --recurse-submodules https://github.com/Garcia6l20/g6-net.git
```

## Build the project

```bash
mkdir build && cd build
conan install --build=missing ..
cmake ..
cmake --build .
```

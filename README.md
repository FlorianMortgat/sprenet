# Compiling the library

```bash
gcc -c -o serpent.o -fPIC serpent.c
gcc -o serpent.so -shared -fPIC serpent.o
```

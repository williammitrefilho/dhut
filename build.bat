C:/mingw64/bin/gcc -I"include" -c httpc.c -o libs/httpc.o
C:/mingw64/bin/gcc -I"include" -c tlsbase.c -o libs/tlsbase.o
::C:/mingw64/bin/gcc -I"include" -c bm256.c -o libs/bm256.o
::C:/mingw64/bin/gcc -I"include" -c gcm.c -o libs/gcm.o
::C:/mingw64/bin/gcc -I"include" -c x25519.c -o libs/x25519.o
::C:/mingw64/bin/gcc -I"include" -c converters.c -o libs/converters.o
::C:/mingw64/bin/gcc -I"include" -c p256.c -o libs/p256.o
::C:/mingw64/bin/gcc -I"include" -c prf.c -o libs/prf.o
::C:/mingw64/bin/gcc -I"include" -c sha.c -o libs/sha.o
C:/mingw64/bin/gcc -I"include" -c gerio.c -o libs/gerio.o
C:/mingw64/bin/gcc -I"include" -c main.c -o main.o
C:/mingw64/bin/gcc libs/bm256.o libs/x25519.o libs/converters.o libs/gerio.o libs/httpc.o libs/tlsbase.o libs/basics.o libs/p256.o libs/sha.o libs/prf.o libs/aes.o libs/cbc.o libs/gcm.o main.o libs/ber_entity.o -o main.exe -lws2_32 -lwinspool
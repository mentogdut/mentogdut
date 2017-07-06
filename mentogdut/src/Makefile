#CC:=gcc
CFLAGS+=-DNDEBUG

objects=mentogdut.o config.o latest_pppoe.o

all: mentogdut 
	@echo mentogdut

objects+= md5.o md4.o sha1.o

ifeq ($(LANG),)
LIBS+= -lws2_32
endif

mentogdut: $(objects)
	$(CC) *.o -Os -o mentogdut $(CFLAGS) $(LIBS)

mentogdut.o: mentogdut.c mentogdut.h
	$(CC) $(CFLAGS) -Os -c $<
config.o: config.c
	$(CC) $(CFLAGS) -Os -c $<
latest_pppoe.o: latest_pppoe.c
	$(CC) $(CFLAGS) -Os -c $<
md5.o md4.o sha1.o:
	$(CC) -Os -c mbedtls/*.c

.PHONY : clean
clean:
ifeq ($(LANG),)
	del mentogdut.exe *.o
else
	$(RM) mentogdut *.o
endif

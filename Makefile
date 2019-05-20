.PHONY: clean install uninstall
CC=gcc
CFLAGS=-Wall -std=c11 -c
ifdef DEBUG
	CFLAGS+=-g -O0
else
	CFLAGS+=-O2
endif
RM=rm -f
CP=cp --no-dereference
LIBS=-lcrypto -lxml2
APPNAME=blocksign
APP_OBJS=argparse.o blocksign.o sslhelper.o main.o s_helpers.o log.o
#LIBSSLHELPER_DIR=../libsslhelper/
#ADDL_LIB_DIRS=-L$(LIBSSLHELPER_DIR)
#ADDL_INC_DIRS=-I$(LIBSSLHELPER_DIR)
INSTALL_PATH=/usr/local/bin/

all:$(APPNAME)

$(APPNAME):$(APP_OBJS) 
	$(CC) $(APP_OBJS) -o $(APPNAME) $(LIBS)

main.o:main.c
	$(CC) $(CFLAGS) main.c

argparse.o:argparse.c
	$(CC) $(CFLAGS) -I/usr/include/libxml2 argparse.c

blocksign.o:blocksign.c
	$(CC) $(CFLAGS) blocksign.c

sslhelper.o:sslhelper.c
	$(CC) $(CFLAGS) sslhelper.c

s_helpers.o:s_helpers.c
	$(CC) $(CFLAGS) s_helpers.c

log.o:log.c
	$(CC) $(CFLAGS) log.c

clean:
	$(RM) *.o $(APPNAME)
	
install:
	$(CP) $(APPNAME) $(INSTALL_PATH)
	
uninstall:
	$(RM) $(INSTALL_PATH)$(APPNAME)

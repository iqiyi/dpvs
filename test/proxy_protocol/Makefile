CC		= gcc
MAKE	= make
RM		= rm

OPTIONS	= -DWITH_IPV6_ENABLE
OPTIONS	+= -DLOG_VERBOSE

ALL		= tcp_server udp_server
OBJS	= $(patsubst %.c, %.o, $(shell find $(SRCDIR) -name '*.c' | sort))
CFLAGS	= -g -O0 $(OPTIONS)

.PHONY: all clean

all: $(ALL)

tcp_server: proxy_protocol.o tcp_server.o
	$(CC) $(CFLAGS) $^ -o $@

udp_server: proxy_protocol.o udp_server.o
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o $(ALL)

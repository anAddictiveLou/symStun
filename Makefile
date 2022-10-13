.PHONY: all clean

all: 
	gcc -o stun_client stun_client.c stun.c -I. -g
clean: 
	rm stun_client
all: duck_wips

duck_wips: duck_wips.c
		gcc -o duck_wips duck_wips.c -lpcap

clean:
		rm -f duck_wips *.o

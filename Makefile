SHARED_OBJECT = pam_xtime.so
DSTDIR = /lib/x86_64-linux-gnu/security/.

pam_xtime.so:	pam_xtime.o
	$(LD) -shared pam_xtime.o -o pam_xtime.so
pam_xtime.o:	pam_xtime.c
	$(CC) -c -fPIC pam_xtime.c
install:	pam_xtime.so
	cp $(SHARED_OBJECT) $(DSTDIR)
clean:
	rm -f *.o *.so

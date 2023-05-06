binder: binder.cc unotify.cc main.cc unotify.h binder.h
	g++ binder.cc unotify.cc main.cc -o binder -Wall -g -O3 -Wl,-Bstatic -lseccomp -Wl,-Bdynamic
clean:
	rm -f binder
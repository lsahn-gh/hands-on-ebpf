CFLAGS := -target bpf \
		  -I/usr/include/$(shell uname -m)-linux-gnu \
		  -g -O2

BINS = hello.bpf.o hello-func.bpf.o

all: $(BINS)

clean:
	rm $(BINS)

hello.bpf.o: %.o: %.c
	clang $(CFLAGS) -c $< -o $@

hello-func.bpf.o: %.o: %.c
	clang $(CFLAGS) -c $< -o $@

BOFNAME := adduserbysamr
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip

all:
	$(CC_x64) -w -o dist/$(BOFNAME).x64.o -c src/$(BOFNAME).c
	$(CC_x86) -w -o dist/$(BOFNAME).x86.o -c src/$(BOFNAME).c
	$(STRIP_x64) --strip-unneeded dist/$(BOFNAME).x64.o
	$(STRIP_x86) --strip-unneeded dist/$(BOFNAME).x86.o

clean:
	rm -f dist/$(BOFNAME).x64.o
	rm -f dist/$(BOFNAME).x86.o
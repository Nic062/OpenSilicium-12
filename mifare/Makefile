TARGET  := mynfc3 mynfc2
WARN    := -Wall 
CFLAGS  := -O2 ${WARN} `pkg-config --cflags libnfc`
LDFLAGS := `pkg-config --libs libnfc` -lfreefare
CC      := gcc

C_SRCS    = $(wildcard *.c)
OBJ_FILES = $(C_SRCS:.c=.o)

all: ${TARGET}

%.o: %.c
	${CC} ${WARN} -c ${CFLAGS}  $< -o $@

mynfc3: mynfc3.o
	${CC} ${WARN} ${LDFLAGS} -o $@ mynfc3.o

mynfc2: mynfc2.o
	${CC} ${WARN} ${LDFLAGS} -o $@ mynfc2.o

#${TARGET}: ${OBJ_FILES}
#	${CC} ${WARN} ${LDFLAGS} -o $@  $(OBJ_FILES)

clean:
	rm -rf *.o ${TARGET}

mrproper: clean
	rm -rf *~

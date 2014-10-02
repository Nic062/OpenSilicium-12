TARGET  := desfire_info desfire_format desfire_capp desfire_rapp
WARN    := -Wall 
CFLAGS  := -O2 ${WARN} `pkg-config --cflags libnfc`
LDFLAGS := `pkg-config --libs libnfc` -lfreefare
CC      := gcc

C_SRCS    = $(wildcard *.c)
OBJ_FILES = $(C_SRCS:.c=.o)

all: ${TARGET}

%.o: %.c
	${CC} ${WARN} -c ${CFLAGS}  $< -o $@

desfire_format: desfire_format.o
	${CC} ${WARN} ${LDFLAGS} -o $@ desfire_format.o

desfire_info: desfire_info.o
	${CC} ${WARN} ${LDFLAGS} -o $@ desfire_info.o

desfire_capp: desfire_capp.o
	${CC} ${WARN} ${LDFLAGS} -o $@ desfire_capp.o

desfire_rapp: desfire_rapp.o
	${CC} ${WARN} ${LDFLAGS} -o $@ desfire_rapp.o

#${TARGET}: ${OBJ_FILES}
#	${CC} ${WARN} ${LDFLAGS} -o $@  $(OBJ_FILES)

clean:
	rm -rf *.o ${TARGET}

mrproper: clean
	rm -rf *~

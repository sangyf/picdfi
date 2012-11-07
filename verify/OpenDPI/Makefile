CC=gcc
WARN=-Wall
LIB=-lopendpi -lpcap
# change this to your opendpi install path
INC=-I /usr/local/include/libopendpi-1.3/libopendpi/
OBJ=opendpi
SYM=OpenDPI_demo.c

all:
	$(CC) $(WARN) $(LIB) $(INC) $(SYM) -o $(OBJ)

clean:
	rm $(OBJ)

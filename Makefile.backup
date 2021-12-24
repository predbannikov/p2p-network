BOOST_ROOT = /usr/include/boost_1_78_0
BOOST_INC = ${BOOST_ROOT}/include
CXXFLAGS = -g -O0 -std=c++17
all_files = p2p-network.o raw-to.o
all_arguments = -pthread -lboost_system -lboost_thread
TARGET = p2p-network
CC = g++

all: $(all_files)
	$(CC) -o $(TARGET) $(all_files) $(all_arguments)  

p2p-network.o: p2p-network.cpp
	$(CC) -g -O0 -c p2p-network.cpp -I $(BOOST_ROOT) 

raw-to.o: raw-to.cpp
	$(CC) -g -O0 -c raw-to.cpp -I $(BOOST_ROOT)

clean:
	rm $(TARGET) $(all_files)

CXXFLAGS=-g -O0 -std=c++17
all_files = p2p-network.o
all_arguments = -pthread -lboost_system -lboost_thread
TARGET = p2p-network
CC = g++

all: $(all_files)
	$(CC) -o $(TARGET) $(all_files) $(all_arguments)  

main.o: main.cpp 
	$(CC) -c p2p-network.cpp 

clean:
	rm $(TARGET) $(all_files)

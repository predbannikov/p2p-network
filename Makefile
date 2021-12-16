all_files = main.o

all: $(all_files)
	g++ -o p2p-network $(all_files)

main.o: main.cpp
	g++ -c main.cpp

clean:
	rm p2p-network $(all_files)

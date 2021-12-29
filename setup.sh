#! /bin/bash
if [ "$EUID" -ne 0 ]
	then echo "Please run as root or sudo user"
	echo "would you like start this script now as root?"
	while true; do
		read -p "yes/no Y/n " yn
		case $yn in
			[Yy]* ) su root -c "/bin/bash $0;"  ; break;;
			[Nn]* ) exit;;
			* ) echo "Please answer yes or no.";;
		esac
	done
fi		

if [ "$EUID" -ne 0 ]
	then exit
fi

if ! command -v g++ &> /dev/null
then
	echo "g++ could not be found"
	if ! command -v apt &> /dev/null
	then
		echo "apt could not be found"
		exit
	fi
	apt install -y g++ libicu-dev
fi

if ! command -v make &> /dev/null
then
	echo "make could not be found"
	apt install -y make
fi

echo "current directory $(pwd)"
echo "change directory to $HOME" 
pushd ~
mkdir boost
cd boost

wget https://boostorg.jfrog.io/artifactory/main/release/1.78.0/source/boost_1_78_0.tar.gz
tar -xzvf boost_1_78_0.tar.gz
cd boost_1_78_0/
./bootstrap.sh
./b2 install --prefix=/usr
popd



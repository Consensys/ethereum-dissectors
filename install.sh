echo please enter the path to your wireshark build ie 'x/x/Wireshark'
read filename

mkdir $filename/plugins/epan/devp2p
cp packet-ethereum.c C$filename/plugins/epan/devp2p/.
cp CMakeLists.txt $filename/plugins/epan/devp2p/.
cp Makefile.am $filename/plugins/epan/devp2p/.
cp README $filename/plugins/epan/devp2p/.
cp Custom.m4 $filename/plugins/epan/devp2p/.
cp Custom.make $filename/plugins/epan/devp2p/.
cp CMakeListsCustom.txt $filename/.
cd $filename/build && cmake ..
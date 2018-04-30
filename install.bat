ECHO OFF
set /p wireshark="enter wireshark source root"
mkdir -p %wireshark%\plugins\epan\devp2p
copy packet-ethereum.c C:\Development\Wireshark\plugins\epan\devp2p\.
copy CMakeLists.txt C:\Development\Wireshark\plugins\epan\devp2p\.
copy Makefile.am C:\Development\Wireshark\plugins\epan\devp2p\.
copy README C:\Development\Wireshark\plugins\epan\devp2p\.
copy Custom.m4 C:\Development\Wireshark\plugins\epan\devp2p\.
copy Custom.make C:\Development\Wireshark\plugins\epan\devp2p\.
copy CMakeListsCustom.txt C:\Development\Wireshark\.

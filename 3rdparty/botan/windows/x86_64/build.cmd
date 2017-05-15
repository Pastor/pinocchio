@echo off
echo Download https://github.com/randombit/botan/archive/master.zip
echo unzip master.zip
echo python configure.py --disable-shared
echo copy build/include, *.lib, *.dll and *.dll.manifest to this directory

rem set MINGW path
rem gendef botan.dll
rem dlltool --as-flags=--64 -m i386:x86-64 -k --output-lib libbotan.a --input-def botan.def
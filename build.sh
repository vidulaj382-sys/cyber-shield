#!/bin/sh
# Build with MSYS2 UCRT64 (pacman -S mingw-w64-ucrt-x86_64-fltk mingw-w64-ucrt-x86_64-gcc).
# Run from an MSYS2 UCRT64 shell, or from anywhere via:
#   C:\msys64\usr\bin\bash.exe -lc "MSYSTEM=UCRT64 sh /c/Users/Mankeshwari/CyberShield/build.sh"
#
# Step 1 builds and runs the console tests (core only, no FLTK).
# Step 2 builds the GUI program CyberShield.exe.
set -e
cd "$(dirname "$0")"
export PATH=/ucrt64/bin:$PATH
FLAGS="-std=c++17 -Wall -Wextra -O2"

echo "== Building and running core tests =="
g++ $FLAGS tests/core_tests.cpp core/*.cpp -static -o core_tests.exe
./core_tests.exe

echo "== Building CyberShield.exe =="
g++ $FLAGS $(fltk-config --cxxflags) \
    main.cpp core/*.cpp gui/*.cpp \
    $(fltk-config --ldstaticflags) -static -o CyberShield.exe
echo "Built CyberShield.exe"

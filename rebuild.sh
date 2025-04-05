#!/bin/sh
set -xeo pipefail
rm -rf dist/*
export GHIDRA_INSTALL_DIR=$HOME/src/ghidra_11.2_PUBLIC/
gradle buildExtension
FILE="$PWD/dist/*"
mkdir -p ~/Library/ghidra/ghidra_11.2_PUBLIC/Extensions
cd ~/Library/ghidra/ghidra_11.2_PUBLIC/Extensions
rm -rf F32Ghidra
unzip $FILE
~/src/ghidra_11.2_PUBLIC/ghidraRun

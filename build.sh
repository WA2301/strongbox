#!/bin/sh

pyinstaller -F strongbox.py 
rm -rf build *.spec
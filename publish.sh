#!/bin/bash

# Remove former distributions
rm dist/feistel_py-*
rm dist/feistel-py-*

# Publish library to PyPI

python3 -m build
python3 -m twine upload dist/*

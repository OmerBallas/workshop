#!/bin/bash

python3 setup.py build_ext --inplace
python3 http-user.py

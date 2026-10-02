#!/bin/sh

cp "$(readlink -f ./venv/bin/python)" ./venv/bin/python-raw
sudo setcap cap_net_raw+ep ./venv/bin/python-raw

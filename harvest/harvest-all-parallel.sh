#!/bin/bash

cd ~/ohs
~/harvest/list-harvest-all-commands.sh | ~/harvest/parallel/parallel -j 10

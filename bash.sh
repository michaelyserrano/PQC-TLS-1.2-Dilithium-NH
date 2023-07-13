#!/bin/bash

date
for ((n=0;n<500;n++))
do
    echo $n
    ./client newhope 1
    sleep 2.5
done
date

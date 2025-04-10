#!/bin/bash

for fil in ./examples/*.py; do
  python $fil;
  sleep 2;
done


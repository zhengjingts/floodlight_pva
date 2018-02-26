#!/bin/bash

cat log | grep "Experiment - Event - Channel State Changed" > state.log
cat log | grep "Debug - Record" > record.log

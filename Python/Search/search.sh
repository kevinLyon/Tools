#!/bin/bash

FILE_TO_SEARCH="$1"
grep -E "\.$1(?:onp?)?$"

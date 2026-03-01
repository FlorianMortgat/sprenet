#!/bin/bash

# TODO: écrire un script "configure.sh" pour configurer les variables

CC=gcc

PY_LIBS='/usr/lib/x86_64-linux-gnu'
PY_INCLUDE='/usr/include/python3.13'

PY_SHARED_OBJECT='python3.13'


COMPILE_TO_OBJ=(
  "$CC"
  "-c"
  "-o" "serpent.o"
  #"-I$PY_INCLUDE"
  "-fPIC"
  "serpent.c"
)


echo "${COMPILE_TO_OBJ[@]}"

COMPILE_OBJ_TO_SO=(
  "$CC"
  "-o" "serpent.so"
  "-shared"
  #"-L$PY_LIBS"
  #"-l$PY_SHARED_OBJECT"
  "-fPIC"
  "serpent.o"
  )

echo "${COMPILE_OBJ_TO_SO[@]}"

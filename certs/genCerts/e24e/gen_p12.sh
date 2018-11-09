#!/bin/bash

if [ $# -gt 0 ]; then
    openssl x509 -in 02_${1}_BC.x509 -inform DER -out 02_${1}_BC.pem -outform PEM
    openssl pkcs8 -inform DER -nocrypt -in 02_${1}_BC.pkcs8 -out 02_${1}_pk.pem
    openssl pkcs12 -export -out ${1}.p12 -inkey 02_${1}_pk.pem -in 02_${1}_BC.pem -password pass:${1}
    echo Generated ${1}.p12
    echo ${1} > ${1}-p12pwd.txt
    echo Generated ${1}-p12pwd.txt
else
    echo "Your command line contains no arguments"
    exit
fi




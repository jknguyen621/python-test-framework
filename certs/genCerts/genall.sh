exe/i5sim -g bc1,$1 -m $1
exe/i5sim -g dl11,$1 -m $1
./gen_p12.sh $1
mv 02_$1_BC.pkcs8 02_$1.pkcs8

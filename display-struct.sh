cd $1

for i in {0..20}; do 
	echo "ECALL " $i
	python3 ~/kafl/tools/display-structs.py sgx_workdir/ $i | uniq
done

cd ..

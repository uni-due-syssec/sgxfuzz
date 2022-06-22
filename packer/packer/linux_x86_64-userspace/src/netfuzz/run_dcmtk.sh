export DCMDICTPATH=/home/kafl/aflnet/dcmtk/dcmdata/data/dicom.dic
cd ~/aflnet/dcmtk/build/bin
LD_PRELOAD=../../..//hook/inject_debug.so ./dcmqrscp
cd -

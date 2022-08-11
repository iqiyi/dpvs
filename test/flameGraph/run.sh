#!/bin/bash

#perf record -e cpu-clock -g -C 1

[ $# -lt 2 ] && echo -e "[usage]: $0 {perf.data.file} {out.file}" && exit 1

infile=$1
outfile=$2
[ ! -f $infile ] && echo -e "can't find input perf.data file $inflie, please use `perf record` to generate it"
[ _$outfile = _ ] && echo -e "invalid out.file name" && exit 1

perf script -i $infile > perf.unfold
./stackcollapse-perf.pl perf.unfold &> perf.folded
./flamegraph.pl perf.folded > $outfile.svg
rm -f perf.unfold 
rm -f perf.folded 
echo "succeed to generate $outfile.svg"

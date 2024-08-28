if [ $# -ne 1 ]
then
   echo " USAGE: ./ue-ip-search6_stream28.sh  <max interface no>"
   echo "."
   echo "RECALL: nt3g0 - nt3g9 is 10 interfaces"

else
  ./ue-ip-search6.sh  nt3g $1 203.78.47.209 203.78.47.210 203.78.47.211 203.78.47.212 203.78.47.213
fi

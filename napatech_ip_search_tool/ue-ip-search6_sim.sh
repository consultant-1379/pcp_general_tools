if [ $# -ne 1 ]
then
   echo " USAGE: ./ue-ip-search6_sim.sh  <max interface no>"

else
  ./ue-ip-search6.sh  nt3g $1 127.0.0.2 127.0.0.2 127.0.0.2 127.0.0.2 127.0.0.2
fi

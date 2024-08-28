./stop_Gn_Simulator.bsh 1
sleep 5
ds=eth6
us=eth5

/root/gn-sim/simulator_newGtpc_26May14 -i $ds -u $us -t 10000000 -m 840000 gtp-hack/cells.cfg gtp-hack/gn.cfg gtp-hack/trafficAllProtocols.cfg gtp-hack/ue_config_50k_1&
sleep 10
/root/gn-sim/simulator_newGtpc_26May14 -i $ds -u $us -t 10000000 -m 840000 gtp-hack/cells.cfg gtp-hack/gn.cfg gtp-hack/trafficAllProtocols.cfg gtp-hack/ue_config_50k_2&
sleep 10
/root/gn-sim/simulator_newGtpc_26May14 -i $ds -u $us -t 10000000 -m 840000 gtp-hack/cells.cfg gtp-hack/gn.cfg gtp-hack/trafficAllProtocols.cfg gtp-hack/ue_config_50k_3&
sleep 10
/root/gn-sim/simulator_newGtpc_26May14 -i $ds -u $us -t 10000000 -m 840000 gtp-hack/cells.cfg gtp-hack/gn.cfg gtp-hack/trafficAllProtocols.cfg gtp-hack/ue_config_50k_4&
sleep 10
/root/gn-sim/simulator_newGtpc_26May14 -i $ds -u $us -t 10000000 -m 840000 gtp-hack/cells.cfg gtp-hack/gn.cfg gtp-hack/trafficAllProtocols.cfg gtp-hack/ue_config_50k_5&
sleep 10
/root/gn-sim/simulator_newGtpc_26May14 -i $ds -u $us -t 10000000 -m 840000 gtp-hack/cells.cfg gtp-hack/gn.cfg gtp-hack/trafficAllProtocols.cfg gtp-hack/ue_config_50k_6&
sleep 10



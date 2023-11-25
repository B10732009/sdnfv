.PHONY: install uninstall topo upload clean 

GROUP_ID=nctu.winlab
ARTIFACT_ID=ProxyArp
VERSION=1.0-SNAPSHOT
ONOS_APP_NAME=nctu.winlab.proxyarp.app

CUSTOMIZED_TOPO_SCRIPT=topo.py
CUSTOMIZED_TOPO=MyTopo

install:
	cd ${ARTIFACT_ID}; mvn clean install -DskipTests
	onos-app localhost install! ${ARTIFACT_ID}/target/${ARTIFACT_ID}-${VERSION}.oar

uninstall:
	onos-app localhost deactivate ${ONOS_APP_NAME}
	onos-app localhost uninstall ${ONOS_APP_NAME}

# onos:
# 	cd $ONOS_ROOT && bazel run onos-local -- clean debug

# mn:
# 	sudo mn --controller=remote,127.0.0.1:6653 --switch=ovs,protocols=OpenFlow14

# cmn:
# 	sudo mn --custom=${CUSTOMIZED_TOPO_SCRIPT} --topo=${CUSTOMIZED_TOPO} --controller=remote,ip=127.0.0.1:6653 --switch=ovs,protocols=OpenFlow14

topo:
	sudo mn --custom=${CUSTOMIZED_TOPO_SCRIPT} --topo=${CUSTOMIZED_TOPO} --controller=remote,ip=127.0.0.1:6653 --switch=ovs,protocols=OpenFlow14

clean:
	rm -rf ./${ARTIFACT_ID}/target/
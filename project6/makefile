.PHONY: all clean test

all:
	docker compose up -d
	sudo ovs-vsctl add-br mybr
	sudo ovs-docker add-port mybr eth1 R1 --ipaddress=172.20.0.2/24
	sudo ovs-docker add-port mybr eth1 R2 --ipaddress=172.20.0.3/24
	sudo ovs-docker add-port mybr eth2 R3 --ipaddress=172.20.0.4/24
	sudo ovs-vsctl set Bridge mybr protocols=OpenFlow10,OpenFlow13,OpenFlow14
	sudo ovs-vsctl set-controller mybr tcp:127.0.0.1:6653

clean:
	sudo ovs-vsctl del-br mybr
	docker compose down

test:
	docker exec -it h2 ping 172.18.0.3

# up:
# 	docker compose up -d
# down:
# 	docker compose down
# image:
# 	docker image ls
# container:
# 	docker ps -a
# network:
# 	docker network ls
# show:
# 	sudo ovs-vsctl show
# test:
# 	sudo ovs-vsctl add-br mybr
# 	sudo ovs-docker add-port mybr eth1 R1 --ipaddress=172.20.0.2/24
# 	sudo ovs-docker add-port mybr eth1 R2 --ipaddress=172.20.0.3/24
# 	sudo ovs-docker add-port mybr eth2 R3 --ipaddress=172.20.0.4/24
# # sudo ovs-vsctl set Bridge mybridge1 protocols=OpenFlow10,OpenFlow13,OpenFlow14
# # sudo ovs-vsctl set Bridge mybridge2 protocols=OpenFlow10,OpenFlow13,OpenFlow14
# 	sudo ovs-vsctl set Bridge mybr protocols=OpenFlow10,OpenFlow13,OpenFlow14
# 	sudo ovs-vsctl set-controller mybr tcp:127.0.0.1:6653
# test2:
# 	sudo ovs-vsctl del-br mybr
# test3:
	

# cd $ONOS_ROOT && bazel run onos-local -- clean debug
.PHONY: up down image container network test show test2

up:
	docker compose up -d
down:
	docker compose down
image:
	docker image ls
container:
	docker ps -a
network:
	docker network ls
show:
	sudo ovs-vsctl show
test:
	sudo ovs-vsctl add-br mybridge1
	sudo ovs-vsctl add-br mybridge2
	sudo ovs-vsctl add-br mybridge3
aaa:
	sudo ovs-docker add-port mybridge1 veth0 R1 --ipaddress=172.20.0.2/24
	sudo ovs-docker add-port mybridge2 veth0 R2 --ipaddress=172.20.0.3/24
	sudo ovs-docker add-port mybridge3 veth0 R3 --ipaddress=172.20.0.4/24
test2:
	sudo ovs-vsctl del-br mybridge1
	sudo ovs-vsctl del-br mybridge2
	sudo ovs-vsctl del-br mybridge3
# cd $ONOS_ROOT && bazel run onos-local -- clean debug
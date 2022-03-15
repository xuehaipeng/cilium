#!/bin/bash

set -eux

IMG_OWNER=${1:-cilium}
IMG_TAG=${2:-latest}

# With Kind we create two nodes cluster:
#
# * "kind-control-plane" runs cilium in the LB-only mode.
# * "kind-worker" runs the nginx server.
#
# The LB cilium does not connect to the kube-apiserver. For now we use Kind
# just to create Docker-in-Docker containers.
kind create cluster --config kind-config.yaml

# Install Cilium as standalone L4LB: tc/Maglev/SNAT
helm install cilium ../../install/kubernetes/cilium \
    --wait \
    --namespace kube-system \
    --set debug.enabled=true \
    --set image.repository="quay.io/${IMG_OWNER}/cilium-ci" \
    --set image.tag="${IMG_TAG}" \
    --set image.useDigest=false \
    --set image.pullPolicy=IfNotPresent \
    --set operator.enabled=false \
    --set loadBalancer.standalone=true \
    --set loadBalancer.algorithm=maglev \
    --set loadBalancer.mode=snat \
    --set loadBalancer.acceleration=disabled \
    --set devices='{eth0}' \
    --set ipv4.enabled=true \
    --set ipv6.enabled=true \
    --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key="kubernetes.io/hostname" \
    --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=In \
    --set affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]=kind-control-plane

# Disable TX and RX csum offloading, as veth does not support it. Otherwise,
# the forwarded packets by the LB to the worker node will have invalid csums.
IFIDX=$(docker exec -i kind-control-plane \
    /bin/sh -c 'echo $(( $(ip -o l show eth0 | awk "{print $1}" | cut -d: -f1) ))')
LB_VETH_HOST=$(ip -o l | grep "if$IFIDX" | awk '{print $2}' | cut -d@ -f1)
ethtool -K $LB_VETH_HOST rx off tx off

docker exec kind-worker /bin/sh -c 'apt-get update && apt-get install -y nginx && systemctl start nginx'
WORKER_IP6=$(docker exec kind-worker ip -o -6 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
WORKER_IP4=$(docker exec kind-worker ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system wait --for=condition=Ready pod "$CILIUM_POD_NAME" --timeout=5m

# NAT 4->6 test suite
#####################

LB_VIP="10.0.0.4"

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
    cilium service update --id 1 --frontend "${LB_VIP}:80" --backends "[${WORKER_IP6}]:80" --k8s-node-port

SVC_BEFORE=$(kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service list)

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf lb list

LB_NODE_IP=$(docker exec kind-control-plane ip -o -4 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
ip r a "${LB_VIP}/32" via "$LB_NODE_IP"

# Issue 10 requests to LB
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80"
done

# Install Cilium as standalone L4LB: XDP/Maglev/SNAT
helm upgrade cilium ../../install/kubernetes/cilium \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.acceleration=native

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system wait --for=condition=Ready pod "$CILIUM_POD_NAME" --timeout=5m

# Check that restoration went fine. Note that we currently cannot do runtime test
# as veth + XDP is broken when switching protocols. Needs something bare metal.
SVC_AFTER=$(kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service list)

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf lb list

[ "$SVC_BEFORE" != "$SVC_AFTER" ] && exit 1

# Install Cilium as standalone L4LB: tc/Maglev/SNAT
helm upgrade cilium ../../install/kubernetes/cilium \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.acceleration=disabled

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system wait --for=condition=Ready pod "$CILIUM_POD_NAME" --timeout=5m

# Check that curl still works after restore
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80"
done

# Install Cilium as standalone L4LB: tc/Random/SNAT
helm upgrade cilium ../../install/kubernetes/cilium \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.algorithm=random

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system wait --for=condition=Ready pod "$CILIUM_POD_NAME" --timeout=5m

# Check that curl also works for random selection
for i in $(seq 1 10); do
    curl -o /dev/null "${LB_VIP}:80"
done

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service delete 1

# NAT 6->4 test suite
#####################

LB_VIP="fd00:cafe::1"

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- \
    cilium service update --id 1 --frontend "[${LB_VIP}]:80" --backends "${WORKER_IP4}:80" --k8s-node-port

SVC_BEFORE=$(kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service list)

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf lb list

LB_NODE_IP=$(docker exec kind-control-plane ip -o -6 a s eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1)
ip -6 r a "${LB_VIP}/128" via "$LB_NODE_IP"

# Issue 10 requests to LB
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80"
done

# Install Cilium as standalone L4LB: XDP/Maglev/SNAT
helm upgrade cilium ../../install/kubernetes/cilium \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.acceleration=native

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system wait --for=condition=Ready pod "$CILIUM_POD_NAME" --timeout=5m

# Check that restoration went fine. Note that we currently cannot do runtime test
# as veth + XDP is broken when switching protocols. Needs something bare metal.
SVC_AFTER=$(kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service list)

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium bpf lb list

[ "$SVC_BEFORE" != "$SVC_AFTER" ] && exit 1

# Install Cilium as standalone L4LB: tc/Maglev/SNAT
helm upgrade cilium ../../install/kubernetes/cilium \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.acceleration=disabled

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system wait --for=condition=Ready pod "$CILIUM_POD_NAME" --timeout=5m

# Check that curl still works after restore
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80"
done

# Install Cilium as standalone L4LB: tc/Random/SNAT
helm upgrade cilium ../../install/kubernetes/cilium \
    --wait \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.algorithm=random

CILIUM_POD_NAME=$(kubectl -n kube-system get pod -l k8s-app=cilium -o=jsonpath='{.items[0].metadata.name}')
kubectl -n kube-system wait --for=condition=Ready pod "$CILIUM_POD_NAME" --timeout=5m

# Check that curl also works for random selection
for i in $(seq 1 10); do
    curl -o /dev/null "[${LB_VIP}]:80"
done

kubectl -n kube-system exec "${CILIUM_POD_NAME}" -- cilium service delete 1

echo "YAY!"

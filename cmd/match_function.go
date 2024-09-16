package validator

import (
    "net"

    v1 "k8s.io/api/core/v1"
    v1net "k8s.io/api/networking/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/klog/v2"

)

// matchIPBlockOrNamespace matches traffic based on IPBlock or NamespaceSelector.
func (p *PolicyValidator) matchIPBlockOrNamespace(peers []v1net.NetworkPolicyPeer, ip string) bool {
    for _, peer := range peers {
        if peer.IPBlock != nil && cidrMatch(peer.IPBlock.CIDR, ip) {
            klog.Infof("Traffic matches CIDR %s", peer.IPBlock.CIDR)
            return true
        }

        if peer.NamespaceSelector != nil {
            klog.Infof("Traffic matches NamespaceSelector")
            return true
        }
    }
    return false
}

// matchPort checks if the traffic matches the port rules.
func (p *PolicyValidator) matchPort(ports []v1net.NetworkPolicyPort, port int) bool {
    for _, portRule := range ports {
        if portRule.Port != nil && portRule.Port.IntVal == int32(port) {
            return true
        }
    }
    return false
}

// isPodMatch checks if a given pod matches the PodSelector in the NetworkPolicy.
func isPodMatch(pod *v1.Pod, selector metav1.LabelSelector) bool {
    for key, value := range selector.MatchLabels {
        if pod.Labels[key] != value {
            return false
        }
    }
    return true
}

// cidrMatch checks if an IP address matches a CIDR block.
func cidrMatch(cidr string, ip string) bool {
    _, cidrNet, err := net.ParseCIDR(cidr)
    if err != nil {
        klog.Errorf("Invalid CIDR format: %v", err)
        return false
    }
    parsedIP := net.ParseIP(ip)
    return cidrNet.Contains(parsedIP)
}

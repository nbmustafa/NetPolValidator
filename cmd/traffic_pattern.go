package validator

import (
    "fmt"
	"strings"
    "strconv"

    v1net "k8s.io/api/networking/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"

)

// RecordTrafficPattern logs observed traffic patterns.
func (p *PolicyValidator) RecordTrafficPattern(namespace, podName, destIP string, port int) {
    key := fmt.Sprintf("%s/%s", namespace, podName)
    if _, exists := p.trafficPatterns[key]; !exists {
        p.trafficPatterns[key] = make(map[string]int)
    }
    ipPortKey := fmt.Sprintf("%s:%d", destIP, port)
    p.trafficPatterns[key][ipPortKey]++
}

// SuggestNetworkPolicy generates a NetworkPolicy based on observed traffic patterns.
func (p *PolicyValidator) SuggestNetworkPolicy(namespace, podName string) (*v1net.NetworkPolicy, error) {
    key := fmt.Sprintf("%s/%s", namespace, podName)
    if patterns, exists := p.trafficPatterns[key]; exists {
        policy := &v1net.NetworkPolicy{
            ObjectMeta: metav1.ObjectMeta{
                Name: fmt.Sprintf("%s-policy", podName),
                Namespace: namespace,
            },
            Spec: v1net.NetworkPolicySpec{
                PodSelector: metav1.LabelSelector{
                    MatchLabels: map[string]string{
                        "app": podName,
                    },
                },
                PolicyTypes: []v1net.PolicyType{v1net.PolicyTypeIngress, v1net.PolicyTypeEgress},
            },
        }

        for ipPort, _ := range patterns {
            parts := strings.Split(ipPort, ":")
            if len(parts) != 2 {
                continue
            }
            destIP := parts[0]
            port, err := strconv.Atoi(parts[1])
            if err != nil {
                continue
            }

            ingressRule := v1net.NetworkPolicyIngressRule{
                Ports: []v1net.NetworkPolicyPort{
                    {
                        Port: &intstr.IntOrString{IntVal: int32(port)},
                    },
                },
                From: []v1net.NetworkPolicyPeer{
                    {
                        IPBlock: &v1net.IPBlock{
                            CIDR: cidrForIP(destIP),
                        },
                    },
                },
            }
            policy.Spec.Ingress = append(policy.Spec.Ingress, ingressRule)
        }

        klog.Infof("Suggested NetworkPolicy for pod %s in namespace %s: %s", podName, namespace, policy.Name)
        return policy, nil
    }

    return nil, fmt.Errorf("no traffic patterns found for pod %s in namespace %s", podName, namespace)
}

// cidrForIP generates a CIDR block for a given IP address.
func cidrForIP(ip string) string {
    return fmt.Sprintf("%s/32", ip)
}
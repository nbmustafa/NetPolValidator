package validator

import (
    "context"
    "fmt"
    "net"
    "time"

    v1 "k8s.io/api/core/v1"
    v1net "k8s.io/api/networking/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "k8s.io/klog/v2"
    "golang.org/x/time/rate"
    "strings"
    "strconv"
    "k8s.io/apimachinery/pkg/util/intstr"
)

// PolicyValidator handles the validation of NetworkPolicies.
type PolicyValidator struct {
    clientset       *kubernetes.Clientset
    rateLimiter     *rate.Limiter
    trafficPatterns map[string]map[string]int // Map of namespace/pod to destination IP and port
}

// NewPolicyValidator initializes a new PolicyValidator instance.
func NewPolicyValidator() (*PolicyValidator, error) {
    config, err := rest.InClusterConfig()
    if err != nil {
        return nil, fmt.Errorf("failed to load cluster config: %v", err)
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
    }

    // Initialize rate limiter to allow 10 requests per second
    limiter := rate.NewLimiter(rate.Every(time.Second), 10)

    return &PolicyValidator{
        clientset:       clientset,
        rateLimiter:     limiter,
        trafficPatterns: make(map[string]map[string]int),
    }, nil
}

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

// ValidateTraffic checks whether traffic is allowed based on NetworkPolicies.
// The direction parameter specifies whether to validate "ingress", "egress", or "both".
func (p *PolicyValidator) ValidateTraffic(srcPod, srcNamespace, destIP string, port int, direction string) error {
    // Wait for the rate limiter
    if err := p.rateLimiter.Wait(context.TODO()); err != nil {
        return fmt.Errorf("rate limiter error: %v", err)
    }

    pod, err := p.getPod(srcNamespace, srcPod)
    if err != nil {
        return err
    }

    klog.Infof("Validating %s traffic for pod %s in namespace %s", direction, srcPod, srcNamespace)

    // Record the traffic pattern
    p.RecordTrafficPattern(srcNamespace, srcPod, destIP, port)

    // Fetch NetworkPolicies for the namespace
    policies, err := p.clientset.NetworkingV1().NetworkPolicies(srcNamespace).List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        return fmt.Errorf("failed to list network policies in namespace %s: %v", srcNamespace, err)
    }

    var trafficAllowed bool

    for _, policy := range policies.Items {
        if isPodMatch(pod, policy.Spec.PodSelector) {
            klog.Infof("Pod %s matches NetworkPolicy %s", pod.Name, policy.Name)

            // Validate based on direction
            switch direction {
            case "ingress":
                if err := p.checkIngress(policy, srcNamespace, pod, destIP, port); err == nil {
                    trafficAllowed = true
                } else {
                    klog.Errorf("Ingress traffic denied for pod %s due to: %v", pod.Name, err)
                }
            case "egress":
                if err := p.checkEgress(policy, destIP, port); err == nil {
                    trafficAllowed = true
                } else {
                    klog.Errorf("Egress traffic denied for pod %s due to: %v", pod.Name, err)
                }
            case "both":
                if err := p.validateEgressAndIngress(policy, srcNamespace, pod, destIP, port); err == nil {
                    trafficAllowed = true
                } else {
                    klog.Errorf("Traffic denied for pod %s due to: %v", pod.Name, err)
                }
            default:
                return fmt.Errorf("invalid traffic type specified: %s", direction)
            }

            if trafficAllowed {
                break
            }
        }
    }

    if !trafficAllowed {
        klog.Errorf("No policy allows %s traffic for pod %s to IP %s on port %d", direction, srcPod, destIP, port)
    }

    return fmt.Errorf("no policy allows %s traffic for pod %s to IP %s on port %d", direction, srcPod, destIP, port)
}

// getPod fetches a Pod object based on namespace and name.
func (p *PolicyValidator) getPod(namespace, podName string) (*v1.Pod, error) {
    pod, err := p.clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
    if err != nil {
        return nil, fmt.Errorf("failed to retrieve pod %s in namespace %s: %v", podName, namespace, err)
    }
    return pod, nil
}

// validateEgressAndIngress checks both egress and ingress rules.
func (p *PolicyValidator) validateEgressAndIngress(policy v1net.NetworkPolicy, srcNamespace string, pod *v1.Pod, destIP string, port int) error {
    if err := p.checkEgress(policy, destIP, port); err == nil {
        klog.Infof("Egress traffic allowed for pod %s to %s on port %d", pod.Name, destIP, port)
        return nil
    }

    if err := p.checkIngress(policy, srcNamespace, pod, destIP, port); err == nil {
        klog.Infof("Ingress traffic allowed for pod %s from %s on port %d", pod.Name, destIP, port)
        return nil
    }

    klog.Errorf("Neither ingress nor egress rule matched for pod %s", pod.Name)
    return fmt.Errorf("neither ingress nor egress rule matched")
}

// checkEgress checks if the traffic matches any egress rules.
func (p *PolicyValidator) checkEgress(policy v1net.NetworkPolicy, destIP string, port int) error {
    for _, egress := range policy.Spec.Egress {
        if p.matchIPBlockOrNamespace(egress.To, destIP) && p.matchPort(egress.Ports, port) {
            klog.Infof("Egress traffic allowed to %s on port %d", destIP, port)
            return nil
        }
    }
    klog.Errorf("Egress rule does not match destination %s or port %d", destIP, port)
    return fmt.Errorf("egress rule does not match destination %s or port %d", destIP, port)
}

// checkIngress checks if the traffic matches any ingress rules.
func (p *PolicyValidator) checkIngress(policy v1net.NetworkPolicy, srcNamespace string, pod *v1.Pod, destIP string, port int) error {
    for _, ingress := range policy.Spec.Ingress {
        if p.matchIPBlockOrNamespace(ingress.From, destIP) && p.matchPort(ingress.Ports, port) {
            klog.Infof("Ingress traffic allowed from %s on port %d", destIP, port)
            return nil
        }
    }
    klog.Errorf("Ingress rule does not match source %s or port %d", destIP, port)
    return fmt.Errorf("ingress rule does not match source %s or port %d", destIP, port)
}

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

// // handleMasqueradingIP checks if IP masquerading is applied and adjusts the IP for validation.
// func (p *PolicyValidator) handleMasqueradingIP(originalIP string, rewrittenIPs []string) string {
//     for _, ip := range rewrittenIPs {
//         if ip == originalIP {
//             klog.Infof("Masqueraded IP found: %s", ip)
//             return ip
//         }
//     }
//     return originalIP
// }

package validator

import (
    "context"
    "fmt"
    "net"
    "strings"

    v1 "k8s.io/api/core/v1"
    "k8s.io/api/networking/v1beta1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/rest"
    "k8s.io/klog/v2"
)

// PolicyValidator handles the validation of NetworkPolicies.
type PolicyValidator struct {
    clientset *kubernetes.Clientset
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

    return &PolicyValidator{clientset: clientset}, nil
}

// ValidateTraffic checks whether traffic is allowed based on NetworkPolicies.
func (p *PolicyValidator) ValidateTraffic(srcPod string, srcNamespace string, destIP string, port int) error {
    // Fetch source pod and validate
    pod, err := p.clientset.CoreV1().Pods(srcNamespace).Get(context.TODO(), srcPod, metav1.GetOptions{})
    if err != nil {
        return fmt.Errorf("failed to retrieve pod %s: %v", srcPod, err)
    }

    klog.Infof("Validating traffic for pod %s in namespace %s", srcPod, srcNamespace)

    // Get NetworkPolicies in the namespace
    policies, err := p.clientset.NetworkingV1().NetworkPolicies(srcNamespace).List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        return fmt.Errorf("failed to list network policies: %v", err)
    }

    // Check each policy to determine if traffic is allowed
    for _, policy := range policies.Items {
        if isPodMatch(pod, policy.Spec.PodSelector) {
            klog.Infof("Pod %s matches NetworkPolicy %s", pod.Name, policy.Name)

            // Check ingress or egress rules
            if err := p.checkEgress(policy, destIP, port); err == nil {
                klog.Infof("Egress traffic from pod %s to %s on port %d is allowed", srcPod, destIP, port)
                return nil
            }
        }
    }

    return fmt.Errorf("no policy allows egress traffic from pod %s to IP %s on port %d", srcPod, destIP, port)
}

// checkEgress checks if the traffic matches any of the egress rules in the NetworkPolicy.
func (p *PolicyValidator) checkEgress(policy v1beta1.NetworkPolicy, destIP string, port int) error {
    for _, egress := range policy.Spec.Egress {
        for _, to := range egress.To {
            if to.IPBlock != nil {
                if cidrMatch(to.IPBlock.CIDR, destIP) {
                    klog.Infof("Traffic to %s matches CIDR %s", destIP, to.IPBlock.CIDR)
                    return nil
                }
            }
        }

        for _, portRule := range egress.Ports {
            if int(*portRule.Port.IntVal) == port {
                return nil
            }
        }
    }

    return fmt.Errorf("egress rule does not match destination %s or port %d", destIP, port)
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

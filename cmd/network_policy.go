package validator

import (
    "context"
    "fmt"
	"strconv"
	"strings"

    v1 "k8s.io/api/core/v1"
    v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
    "k8s.io/klog/v2"
   
)

// cidrForIP generates a CIDR block for a given IP address.
func cidrForIP(ip string) string {
    return fmt.Sprintf("%s/32", ip)
}

// ValidateTraffic checks whether traffic is allowed based on NetworkPolicies.
// The direction parameter specifies whether to validate "ingress", "egress", or "both".
func (p *PolicyValidator) ValidateTraffic(srcPod, srcNamespace, destIP string, port int, direction string) error {
    // Wait for the rate limiter
    if err := p.rateLimiter.Wait(context.Background()); err != nil {
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

    // Traffic is allowed if there are no NetworkPolicies defined
    if len(policies.Items) == 0 {
        klog.Infof("No NetworkPolicy found for namespace %s. Traffic is allowed.", srcNamespace)
        return nil
    }

    var trafficAllowed bool

    for _, policy := range policies.Items {
        if isPodMatch(pod, policy.Spec.PodSelector) {
            klog.Infof("Pod %s matches NetworkPolicy %s", pod.Name, policy.Name)

            // Check if non-empty ingress/egress sections are present and enforce them
            nonEmptyPolicyEnforced := false

            // Validate based on direction if non-empty sections are not empty
            switch direction {
            case "ingress":
                if !isIngressEmpty(policy) {
                    if err := p.checkIngress(policy, srcNamespace, pod, destIP, port); err == nil {
                        trafficAllowed = true
                    } else {
                        klog.Errorf("Ingress traffic denied for pod %s due to: %v", pod.Name, err)
                    }
                    nonEmptyPolicyEnforced = true
                }
            case "egress":
                if !isEgressEmpty(policy) {
                    if err := p.checkEgress(policy, destIP, port); err == nil {
                        trafficAllowed = true
                    } else {
                        klog.Errorf("Egress traffic denied for pod %s due to: %v", pod.Name, err)
                    }
                    nonEmptyPolicyEnforced = true
                }
            case "both":
                if !isEgressEmpty(policy) || !isIngressEmpty(policy) {
                    if err := p.validateEgressAndIngress(policy, srcNamespace, pod, destIP, port); err == nil {
                        trafficAllowed = true
                    } else {
                        klog.Errorf("Traffic denied for pod %s due to: %v", pod.Name, err)
                    }
                    nonEmptyPolicyEnforced = true
                }
            }

            // If no non-empty policy is enforced, allow traffic if egress/ingress sections are empty
            if !nonEmptyPolicyEnforced {
                if isEgressEmpty(policy) && (direction == "egress" || direction == "both") {
                    klog.Infof("Egress section in policy %s is empty. Egress traffic is allowed.", policy.Name)
                    trafficAllowed = true
                }
                if isIngressEmpty(policy) && (direction == "ingress" || direction == "both") {
                    klog.Infof("Ingress section in policy %s is empty. Ingress traffic is allowed.", policy.Name)
                    trafficAllowed = true
                }
            }

            if trafficAllowed {
                break
            }
        }
    }

    if !trafficAllowed {
        klog.Errorf("No policy allows %s traffic for pod %s to IP %s on port %d", direction, srcPod, destIP, port)
        return fmt.Errorf("no policy allows %s traffic for pod %s to IP %s on port %d", direction, srcPod, destIP, port)
    }

    return nil
}

// isEgressEmpty checks if the egress section of a policy is empty.
func isEgressEmpty(policy v1net.NetworkPolicy) bool {
    return len(policy.Spec.Egress) == 0 || (len(policy.Spec.Egress) == 1 && len(policy.Spec.Egress[0].To) == 0 && len(policy.Spec.Egress[0].Ports) == 0)
}

// isIngressEmpty checks if the ingress section of a policy is empty.
func isIngressEmpty(policy v1net.NetworkPolicy) bool {
    return len(policy.Spec.Ingress) == 0 || (len(policy.Spec.Ingress) == 1 && len(policy.Spec.Ingress[0].From) == 0 && len(policy.Spec.Ingress[0].Ports) == 0)
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

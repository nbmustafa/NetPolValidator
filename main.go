package main

import (
    "context"
    "flag"
    "fmt"
    "net"
    "path/filepath"
    "strings"

    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    networkingv1 "k8s.io/api/networking/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/util/homedir"
)

func main() {
    var kubeconfig *string
    if home := homedir.HomeDir(); home != "" {
        kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
    } else {
        kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
    }
    namespace := flag.String("namespace", "default", "namespace to inspect NetworkPolicies")
    labelSelector := flag.String("labelSelector", "", "label selector to filter pods")
    destIP := flag.String("destIP", "", "destination IP address")
    destPort := flag.Int("destPort", 0, "destination port (required)")
    flag.Parse()

    if *destPort == 0 {
        fmt.Println("Error: --destPort is required")
        return
    }

    if *destIP != "" && !isValidIP(*destIP) {
        fmt.Println("Error: Invalid destination IP address")
        return
    }

    config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
    if err != nil {
        fmt.Printf("Error building kubeconfig: %v\n", err)
        return
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        fmt.Printf("Error creating Kubernetes client: %v\n", err)
        return
    }

    netpols, err := clientset.NetworkingV1().NetworkPolicies(*namespace).List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        fmt.Printf("Error listing NetworkPolicies: %v\n", err)
        return
    }

    fmt.Printf("Checking NetworkPolicies in namespace %s:\n", *namespace)
    for _, netpol := range netpols.Items {
        fmt.Printf("\n- NetworkPolicy: %s\n", netpol.Name)
        checkTraffic(netpol, *labelSelector, *destIP, *destPort)
    }
}

func checkTraffic(netpol networkingv1.NetworkPolicy, labelSelector, destIP string, destPort int) {
    if len(netpol.Spec.Ingress) > 0 {
        fmt.Println("  Ingress rules:")
        for _, ingress := range netpol.Spec.Ingress {
            checkIngress(ingress, netpol.Name, labelSelector, destIP, destPort)
        }
    } else {
        fmt.Println("  No ingress rules found.")
    }

    if len(netpol.Spec.Egress) > 0 {
        fmt.Println("  Egress rules:")
        for _, egress := range netpol.Spec.Egress {
            checkEgress(egress, netpol.Name, labelSelector, destIP, destPort)
        }
    } else {
        fmt.Println("  No egress rules found.")
    }
}

func checkIngress(ingress networkingv1.NetworkPolicyIngressRule, netpolName, labelSelector, destIP string, destPort int) {
    for _, from := range ingress.From {
        if from.PodSelector != nil && matchLabelSelector(from.PodSelector, labelSelector) {
            for _, port := range ingress.Ports {
                if port.Port != nil && port.Port.IntValue() == destPort {
                    fmt.Printf("    Ingress traffic from pods with label selector '%s' to %s:%d is allowed by NetworkPolicy %s\n", labelSelector, destIP, destPort, netpolName)
                }
            }
        }
    }
}

func checkEgress(egress networkingv1.NetworkPolicyEgressRule, netpolName, labelSelector, destIP string, destPort int) {
    for _, to := range egress.To {
        if to.PodSelector != nil && matchLabelSelector(to.PodSelector, labelSelector) {
            for _, port := range egress.Ports {
                if port.Port != nil && port.Port.IntValue() == destPort {
                    fmt.Printf("    Egress traffic to pods with label selector '%s' from %s:%d is allowed by NetworkPolicy %s\n", labelSelector, destIP, destPort, netpolName)
                }
            }
        }

        if to.IPBlock != nil && cidrContainsIP(to.IPBlock.CIDR, destIP) {
            for _, port := range egress.Ports {
                if port.Port != nil && port.Port.IntValue() == destPort {
                    fmt.Printf("    Egress traffic to IPBlock %s (CIDR: %s) on port %d is allowed by NetworkPolicy %s\n", destIP, to.IPBlock.CIDR, destPort, netpolName)
                }
            }
        }
    }
}

// Helper function to match PodSelector to labelSelector
func matchLabelSelector(podSelector *metav1.LabelSelector, labelSelector string) bool {
    for key, value := range podSelector.MatchLabels {
        selectorParts := strings.Split(labelSelector, "=")
        if len(selectorParts) == 2 && key == selectorParts[0] && value == selectorParts[1] {
            return true
        }
    }
    return false
}

// Helper function to validate IP address
func isValidIP(ip string) bool {
    return net.ParseIP(ip) != nil
}

// Helper function to check if a CIDR block contains a specific IP
func cidrContainsIP(cidr, ip string) bool {
    _, ipNet, err := net.ParseCIDR(cidr)
    if err != nil {
        return false
    }
    return ipNet.Contains(net.ParseIP(ip))
}

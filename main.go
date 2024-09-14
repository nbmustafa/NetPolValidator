package main

import (
    "flag"
    "fmt"
    "os"

    "k8s-netpolicy-validator/pkg/validator"
    "k8s.io/klog/v2"
)

// direction represents the type of traffic being validated.
type direction string

const (
    Ingress direction = "ingress"
    Egress  direction = "egress"
    Both    direction = "both"
)

func main() {
    // Command-line flags
    srcPod := flag.String("src-pod", "", "The source pod name")
    srcNamespace := flag.String("src-namespace", "default", "The source pod's namespace")
    destIP := flag.String("dest-ip", "", "The destination IP or CIDR")
    port := flag.Int("port", 0, "The destination port")
    trafficDirection := flag.String("direction", "ingress", "The traffic direction: ingress, egress, or both")
    flag.Parse()

    // Validate input
    if *srcPod == "" || *destIP == "" || *port == 0 {
        fmt.Println("Please provide valid src-pod, dest-ip, and port")
        os.Exit(1)
    }

    // Initialize the policy validator
    validator, err := validator.NewPolicyValidator()
    if err != nil {
        klog.Fatalf("Error initializing PolicyValidator: %v", err)
    }

    // Perform the validation
    err = validator.ValidateTraffic(*srcPod, *srcNamespace, *destIP, *port, *trafficDirection)
    if err != nil {
        klog.Errorf("Traffic validation failed: %v", err)
        os.Exit(1)
    }

    klog.Infof("Traffic for pod %s in namespace %s to IP %s on port %d is allowed.", *srcPod, *srcNamespace, *destIP, *port)
}

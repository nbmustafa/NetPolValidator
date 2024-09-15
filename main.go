package main

import (
    "flag"
    "fmt"
    "os"

    "pkg/validator"
    "k8s.io/klog/v2"
)

// direction represents the type of traffic being validated.
type direction string

const (
    Ingress direction = "ingress"
    Egress  direction = "egress"
    Both    direction = "both"
)

// ANSI escape codes for colors
const (
    ColorReset  = "\033[0m"
    ColorRed    = "\033[31m"
    ColorGreen  = "\033[32m"
    ColorYellow = "\033[33m"
    ColorCyan   = "\033[36m"
    ColorBlue   = "\033[34m"
)

func main() {
    // Command-line flags
    srcPod := flag.String("src-pod", "", "The source pod name")
    srcNamespace := flag.String("namespace", "default", "The source pod's namespace")
    destIP := flag.String("dest-ip", "", "The destination IP or CIDR")
    port := flag.Int("port", 0, "The destination port")
    trafficDirection := flag.String("direction", "ingress", "The traffic direction: ingress, egress, or both")
    flag.Parse()

    // Validate input
    if *srcPod == "" || *destIP == "" || *port == 0 {
        fmt.Printf(ColorRed + "Error: Please provide valid src-pod, dest-ip, and port\n" + ColorReset)
        os.Exit(1)
    }

    // Initialize the policy validator
    validator, err := validator.NewPolicyValidator()
    if err != nil {
        fmt.Printf(ColorRed + "Error initializing PolicyValidator: %v\n" + ColorReset, err)
        os.Exit(1)
    }

    fmt.Printf(ColorBlue + "Validating traffic for pod %s in namespace %s...\n" + ColorReset, *srcPod, *srcNamespace)

    // Perform the validation
    err = validator.ValidateTraffic(*srcPod, *srcNamespace, *destIP, *port, *trafficDirection)
    if err != nil {
        fmt.Printf(ColorRed + "Traffic validation failed: %v\n" + ColorReset, err)
        os.Exit(1)
    }

    fmt.Printf(ColorGreen + "Success: Traffic for pod %s in namespace %s to IP %s on port %d is allowed.\n" + ColorReset, *srcPod, *srcNamespace, *destIP, *port)
}

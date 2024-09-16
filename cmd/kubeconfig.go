package validator

import (
    "fmt"
    "time"

    "k8s.io/client-go/kubernetes"
    "golang.org/x/time/rate"
    "k8s.io/client-go/tools/clientcmd"

)

// PolicyValidator handles the validation of NetworkPolicies.
type PolicyValidator struct {
    clientset       *kubernetes.Clientset
    rateLimiter     *rate.Limiter
    trafficPatterns map[string]map[string]int // Map of namespace/pod to destination IP and port
}

// NewPolicyValidator initializes a new PolicyValidator instance.
func NewPolicyValidator() (*PolicyValidator, error) {
    // Use the KUBECONFIG environment variable or default location
    kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
    
    config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
    if err != nil {
        return nil, fmt.Errorf("failed to load kubeconfig: %v", err)
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

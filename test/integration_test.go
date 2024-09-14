package main

import (
    "flag"
    "testing"
    "os"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/apimachinery/pkg/util/intstr"
    "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/api/networking/v1"
)

func TestIntegration(t *testing.T) {
    kubeconfig := flag.String("kubeconfig", "/path/to/your/kubeconfig", "absolute path to the kubeconfig file")
    flag.Parse()
    
    config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
    if err != nil {
        t.Fatalf("Failed to build kubeconfig: %v", err)
    }
    
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        t.Fatalf("Failed to create Kubernetes client: %v", err)
    }
    
    // Create a NetworkPolicy
    np := &v1.NetworkPolicy{
        ObjectMeta: metav1.ObjectMeta{
            Name: "test-policy",
            Namespace: "default",
        },
        Spec: v1.NetworkPolicySpec{
            PodSelector: metav1.LabelSelector{
                MatchLabels: map[string]string{
                    "app": "test-app",
                },
            },
            Ingress: []v1.NetworkPolicyIngressRule{
                {
                    Ports: []v1.NetworkPolicyPort{
                        {
                            Port: &intstr.IntOrString{IntVal: 80},
                        },
                    },
                    From: []v1.NetworkPolicyPeer{
                        {
                            IPBlock: &v1.IPBlock{
                                CIDR: "10.0.0.0/24",
                            },
                        },
                    },
                },
            },
        },
    }
    
    _, err = clientset.NetworkingV1().NetworkPolicies("default").Create(context.TODO(), np, metav1.CreateOptions{})
    if err != nil {
        t.Fatalf("Failed to create NetworkPolicy: %v", err)
    }
    
    // Run the main function with appropriate flags
    os.Args = []string{"cmd", "-src-pod=test-pod", "-namespace=default", "-dest-ip=10.0.0.1", "-port=80", "-direction=ingress"}
    main()
}

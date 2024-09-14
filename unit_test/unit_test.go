package validator

import (
    "context"
    "testing"
    "time"

    "k8s.io/client-go/kubernetes/fake"
    "k8s.io/client-go/tools/cache"
    "k8s.io/client-go/util/retry"
    "k8s.io/apimachinery/pkg/util/intstr"
    v1 "k8s.io/api/core/v1"
    v1net "k8s.io/api/networking/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "golang.org/x/time/rate"
    "github.com/stretchr/testify/assert"
)

func TestRecordTrafficPattern(t *testing.T) {
    p := &PolicyValidator{
        trafficPatterns: make(map[string]map[string]int),
    }

    p.RecordTrafficPattern("default", "pod1", "192.168.1.1", 80)
    p.RecordTrafficPattern("default", "pod1", "192.168.1.1", 80)

    patterns := p.trafficPatterns["default/pod1"]
    assert.NotNil(t, patterns)
    assert.Equal(t, 2, patterns["192.168.1.1:80"])
}

func TestSuggestNetworkPolicy(t *testing.T) {
    p := &PolicyValidator{
        trafficPatterns: map[string]map[string]int{
            "default/pod1": {
                "192.168.1.1:80": 5,
            },
        },
    }

    policy, err := p.SuggestNetworkPolicy("default", "pod1")
    assert.NoError(t, err)
    assert.Equal(t, "pod1-policy", policy.Name)
    assert.Len(t, policy.Spec.Ingress, 1)
}

func TestValidateTraffic(t *testing.T) {
    clientset := fake.NewSimpleClientset()
    p := &PolicyValidator{
        clientset:       clientset,
        rateLimiter:     rate.NewLimiter(rate.Every(time.Second), 10),
        trafficPatterns: make(map[string]map[string]int),
    }

    pod := &v1.Pod{
        ObjectMeta: metav1.ObjectMeta{
            Name:      "pod1",
            Namespace: "default",
            Labels:    map[string]string{"app": "pod1"},
        },
    }
    _, err := clientset.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})
    assert.NoError(t, err)

    policy := &v1net.NetworkPolicy{
        ObjectMeta: metav1.ObjectMeta{
            Name:      "pod1-policy",
            Namespace: "default",
        },
        Spec: v1net.NetworkPolicySpec{
            PodSelector: metav1.LabelSelector{
                MatchLabels: map[string]string{"app": "pod1"},
            },
            Ingress: []v1net.NetworkPolicyIngressRule{
                {
                    Ports: []v1net.NetworkPolicyPort{
                        {
                            Port: &intstr.IntOrString{IntVal: 80},
                        },
                    },
                    From: []v1net.NetworkPolicyPeer{
                        {
                            IPBlock: &v1net.IPBlock{
                                CIDR: "192.168.1.1/32",
                            },
                        },
                    },
                },
            },
        },
    }
    _, err = clientset.NetworkingV1().NetworkPolicies("default").Create(context.TODO(), policy, metav1.CreateOptions{})
    assert.NoError(t, err)

    err = p.ValidateTraffic("pod1", "default", "192.168.1.1", 80, "ingress")
    assert.NoError(t, err)
}

func TestCidrs(t *testing.T) {
    assert.Equal(t, "192.168.1.1/32", cidrForIP("192.168.1.1"))
}

func TestCidrsMatch(t *testing.T) {
    assert.True(t, cidrMatch("192.168.1.1/32", "192.168.1.1"))
    assert.False(t, cidrMatch("192.168.1.1/32", "192.168.1.2"))
}

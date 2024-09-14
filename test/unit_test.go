package validator

import (
    "context"
    "testing"

    v1 "k8s.io/api/core/v1"
    v1net "k8s.io/api/networking/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes/fake"
    "golang.org/x/time/rate"
    "github.com/stretchr/testify/assert"
)

func TestNewPolicyValidator(t *testing.T) {
    pv, err := NewPolicyValidator()
    assert.NoError(t, err)
    assert.NotNil(t, pv)
}

func TestRecordTrafficPattern(t *testing.T) {
    pv := &PolicyValidator{
        trafficPatterns: make(map[string]map[string]int),
    }
    pv.RecordTrafficPattern("default", "pod1", "10.0.0.1", 80)
    
    patterns := pv.trafficPatterns["default/pod1"]
    assert.Equal(t, 1, patterns["10.0.0.1:80"])
}

func TestSuggestNetworkPolicy(t *testing.T) {
    pv := &PolicyValidator{
        trafficPatterns: map[string]map[string]int{
            "default/pod1": {
                "10.0.0.1:80": 5,
            },
        },
    }
    
    policy, err := pv.SuggestNetworkPolicy("default", "pod1")
    assert.NoError(t, err)
    assert.Equal(t, "pod1-policy", policy.Name)
    assert.Equal(t, "default", policy.Namespace)
    assert.Len(t, policy.Spec.Ingress, 1)
    assert.Equal(t, int32(80), *policy.Spec.Ingress[0].Ports[0].Port.IntVal)
}

func TestValidateTraffic(t *testing.T) {
    fakeClient := fake.NewSimpleClientset(&v1net.NetworkPolicy{
        ObjectMeta: metav1.ObjectMeta{
            Name: "test-policy",
            Namespace: "default",
        },
        Spec: v1net.NetworkPolicySpec{
            PodSelector: metav1.LabelSelector{
                MatchLabels: map[string]string{
                    "app": "pod1",
                },
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
                                CIDR: "10.0.0.0/24",
                            },
                        },
                    },
                },
            },
        },
    })
    
    pv := &PolicyValidator{
        clientset:   fakeClient,
        rateLimiter: rate.NewLimiter(rate.Every(time.Second), 10),
    }
    
    err := pv.ValidateTraffic("pod1", "default", "10.0.0.1", 80, "ingress")
    assert.NoError(t, err)
    
    err = pv.ValidateTraffic("pod1", "default", "10.0.0.1", 8080, "ingress")
    assert.Error(t, err)
}

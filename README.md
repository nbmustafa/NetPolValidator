# NetPolValidator
A Golang tool to simulates and validates Kubernetes NetworkPolicy connectivity

NetPolValidator is a Golang tool to validate Kubernetes NetworkPolicy ingress and egress traffic, the tool can validate both ingress and egress traffic with respect to Kubernetes NetworkPolicies, including label matching, CIDR checks, and namespace selectors. This tool will allow users to specify source pods, namespaces, destination IPs or CIDR ranges, and port numbers.

### Features Breakdown
- Label Matching: The isPodMatch function checks if the source pod matches the PodSelector in a NetworkPolicy, ensuring robust label matching.
- CIDR Matching: The cidrMatch function validates whether a destination IP falls within a CIDR range defined in the NetworkPolicy.
- NamespaceSelector: In both checkIngress and checkEgress, the NamespaceSelector is considered when determining if traffic is allowed based on policy rules.
- Egress Traffic Validation: the tool can validate outgoing traffic based on the NetworkPolicy egress rules.
- Ingress Traffic Validation: the tool can validate incoming traffic based on the NetworkPolicy ingress rules.
- Error Handling: Errors such as invalid IPs, unmatched labels, or missing policies are logged and reported clearly.


How to run:
``` 
go run main.go --src-pod=my-pod --namespace=default --dest-ip=192.168.1.10 --port=8080 --direction=egress
go run main.go --src-pod=my-pod --namespace=default --dest-ip=192.168.1.10 --port=8080 --direction=ingress
go run main.go --src-pod=my-pod --namespace=default --dest-ip=192.168.1.10 --port=8080 --direction=both

```

### How the tool works:
- The tool first gets the all netpolicies in the specified namespace
- Then it checks each policy for both ingress and egress rules
    - checks if Egress traffic is allowed or not
    - checks if ingress traffic is allowed or not
        - how does above two steps are checked:
            - isPodMatch checks if a given pod matches the PodSelector in the NetworkPolicy
            - cidrMatch checks if an IP address matches a CIDR block in the NetworkPolicy


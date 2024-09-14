# NetPolValidator
A Golang tool to simulates and validates Kubernetes NetworkPolicy connectivity

NetPolValidator is a Golang tool to validate Kubernetes NetworkPolicy ingress and egress traffic can be structured as follows. This tool will allow users to specify source pods, namespaces, destination IPs or CIDR ranges, and port numbers. It will feature robust label matching for pods, CIDR support, namespace selectors, and proper error handling/reporting.

Here’s an outline and implementation of key components:

### Features Breakdown
- Label Matching: The isPodMatch function checks if the source pod matches the PodSelector in a NetworkPolicy, ensuring robust label matching.
- CIDR Matching: The cidrMatch function validates whether a destination IP falls within a CIDR range defined in the NetworkPolicy.
- NamespaceSelector: In both checkIngress and checkEgress, the NamespaceSelector is considered when determining if traffic is allowed based on policy rules.
- Egress Traffic Validation: the tool can validate outgoing traffic based on the NetworkPolicy egress rules.
- Ingress Traffic Validation: the tool can validate incoming traffic based on the NetworkPolicy ingress rules.
NamespaceSelector: You can now filter traffic based on namespaceSelector for both ingress and egress traffic.
- Error Handling: Errors such as invalid IPs, unmatched labels, or missing policies are logged and reported clearly.


How to run:
``` 
go run main.go --src-pod=my-pod --src-namespace=default --dest-ip=192.168.1.10 --port=8080
```


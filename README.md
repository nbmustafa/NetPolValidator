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
- A rate-limiting feature to prevent the validator from being overwhelmed by too many requests in a short time, which could be helpful in large clusters or when integrated into a CI/CD pipeline.
- Automated Policy Suggestion: a feature that suggests a NetworkPolicy based on observed traffic patterns. This could be useful for teams to automatically generate policies based on actual traffic flows, reducing manual policy creation.

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

#### Flow Chart Diagram:
```
Start
  |
  V
Initialize PolicyValidator
  |-- Load cluster config
  |-- Create Kubernetes client
  |-- Initialize rate limiter
  |
  V
Record Traffic Pattern
  |-- Input: Namespace, Pod Name, Dest IP, Port
  |-- Record pattern in trafficPatterns
  |
  V
Suggest Network Policy
  |-- Input: Namespace, Pod Name
  |-- Check if traffic patterns exist
  |-- Create NetworkPolicy based on patterns
  |-- Add Ingress rules
  |-- Output: Suggested NetworkPolicy
  |
  V
Validate Traffic
  |-- Input: Source Pod, Source Namespace, Dest IP, Port, Direction
  |-- Wait for rate limiter
  |-- Fetch pod details
  |-- Record traffic pattern
  |-- Fetch NetworkPolicies for namespace
  |-- For each NetworkPolicy:
      |-- Check if pod matches policy
      |-- Validate traffic based on direction
          |-- Check Ingress rules
          |-- Check Egress rules
          |-- Validate both if direction is Both
  |-- Output: Traffic validation result
  |
  V
End

Helper Functions
  |-- getPod
  |-- validateEgressAndIngress
  |-- checkEgress
  |-- checkIngress
  |-- matchIPBlockOrNamespace
  |-- matchPort
  |-- isPodMatch
  |-- cidrMatch

```

In the flowchart:
- Initialization sets up the environment.
- Record Traffic Pattern logs observed traffic data.
- Suggest Network Policy uses recorded data to recommend a policy.
- Validate Traffic checks if the traffic complies with existing policies.
- Helper Functions support the core functionality with specific tasks.

### upcoming features and improvements
- Notification System: Integrate with a notification system to alert stakeholders when policies are changed or traffic issues are detected.
-  Enhanced Logging and Metrics: Add detailed metrics collection for traffic patterns, policy application, and validation results to monitor and analyze the effectiveness of policies.


### Where this tool can be used:
- Platform engineers and developers to validate their netpol during new implementation or for incident troubleshooting. 
- CI/CD Integration: Integrate policy validation into CI/CD pipelines to automatically validate policies as part of the deployment process.
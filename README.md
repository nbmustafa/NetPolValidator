# NetPolValidator
A Golang tool to simulates and validates Kubernetes NetworkPolicy connectivity

NetPolValidator is a Golang tool to validate Kubernetes NetworkPolicy ingress and egress traffic can be structured as follows. This tool will allow users to specify source pods, namespaces, destination IPs or CIDR ranges, and port numbers. It will feature robust label matching for pods, CIDR support, namespace selectors, and proper error handling/reporting.

Here’s an outline and implementation of key components:



How to run:
``` 
go run main.go --src-pod=my-pod --src-namespace=default --dest-ip=192.168.1.10 --port=8080
```


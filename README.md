# Hailcannon

1. Hailcannon gets a list of customers with active bastions from keelhaul. 
2. Creates a hacker for each customer, and provides that hacker with a grpc connection to bezos as well as SpanxCredentials (sts credentials).
3. Hacker then periodically calls to bezosphere for a list of security groups, and updates the bastion ingress stack.
4. The ingress rules in the bastion ingress stack allow the bastion to talk to things in its VPC.

![a hailcannon](/hc.jpg?raw=true)


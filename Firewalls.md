# Firewall Exploration Lab


First, we started the respective containers.
![Containers](https://github.com/user-attachments/assets/0763329e-f5ca-48dd-81d9-789f7b1e38e6)

## Task 2.A

![Screenshot 2025-06-14 124652](https://github.com/user-attachments/assets/eb0d765f-2700-4197-a760-a3ef0960f25f)


Ping from Host 2 to Host 1:

![Screenshot 2025-06-14 130439](https://github.com/user-attachments/assets/eba9d0c3-730e-4601-9563-fa6f52d2c845)


## Task 2.B

- (Can ping from Host A to router but not the other Internal host fails to ping such host1, host2, host3)

![Screenshot 2025-06-14 125928](https://github.com/user-attachments/assets/716c6466-855c-4404-b54d-39cb68db3216)


## Task 2.C 
- Internal to external hosts pings after applying firewall rules

![Screenshot 2025-06-14 131028](https://github.com/user-attachments/assets/cf09ac5f-5683-49e1-a618-3fbedfff0000)


## Task 3.A 
- We observed conntrack timeout in 29 seconds

UDP Experiment:

![Screenshot 2025-06-14 134712](https://github.com/user-attachments/assets/bf7bba5d-ceb8-4f8f-881c-a615bfd3486a)


TCP Experiment:

![Screenshot 2025-06-14 134053](https://github.com/user-attachments/assets/4efa3457-1e00-4e0f-8b7f-34e7f01ede7b)


## Task 3.B

Stateful Firewall 
- Tracks connections (NEW, ESTABLISHED, RELATED).
- More secure—only allows valid, tracked traffic.
- Simpler rules—automatically handles replies.
- Slightly slower due to connection tracking.

Stateless Firewall
- No connection tracking—only checks packet headers (IP, port, flags).
- Faster (no tracking overhead).
- Less secure—requires manual rules for responses, prone to misconfigurations.
- Harder to manage—complex rules for dynamic protocols.

### Best Choice: Stateful firewall for security, stateless only if performance is critical.

## Task 4

1. Rate Limiting

What it does:
- Allows packets from 10.9.0.5 at a controlled rate.
- --limit 10/minute: Permits 10 packets per minute on average.
- --limit-burst 5: Allows an initial burst of 5 packets before rate limiting kicks in.
Observation when only this rule is active:
- First 5 pings (burst) will succeed immediately.
- After that, packets are limited to ~10 per minute (1 every 6 seconds).
- Excess packets are not dropped yet—they just get delayed.
2. Explicit drop

What it does:
- Drops all packets from 10.9.0.5 that exceed the rate limit.
- Why it’s needed:
    - Without this rule, the limit module only delays packets (they stay in a queue).
    - Attackers could still flood the network—packets would just be slowed down, not blocked.
    - The DROP rule ensures strict enforcement—exceeding the limit = packets are discarded.

### Yes, the DROP rule is necessary because:
- The limit module alone does not block traffic—it only slows it down.
- Without DROP, an attacker could flood the network with delayed packets, consuming resources.
- The DROP rule ensures hard enforcement of the rate limit, improving security.

![Screenshot 2025-06-14 140634](https://github.com/user-attachments/assets/19a0c494-8509-4270-b779-826a5f8e8f01)


## Task 5 

![Screenshot 2025-06-14 144427](https://github.com/user-attachments/assets/506d7732-0c9d-464a-b8d6-4ffe5bdf06a9)

We have applied the rules but were not able to receive messages on the internals hosts.

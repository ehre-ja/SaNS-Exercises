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
- (conntrack timeout in seconds (29 seconds)

UDP Experiment:
![Screenshot 2025-06-14 131028](https://github.com/user-attachments/assets/2d2e25b0-a2ca-451f-b39a-3d1468aec1d1)

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

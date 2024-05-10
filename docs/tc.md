# TC

Traffic Control 是 linux 提供的进行流量控制的子系统.

## 网络模拟

清除模拟策略

```txt
tc qdisc del dev eth0 root netem
```

延时,乱序,丢包,重复,损坏

```txt
tc qdisc add dev eth0 root netem delay 100ms 20ms reorder 25% 10% loss 5% distribution normal duplicate 6% corrupt 7%
```

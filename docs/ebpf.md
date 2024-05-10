# eBPF

## Tracepoint

可用的 tracepoint 保存在 `/sys/kernel/debug/tracing/available_events`.

每行为一个 hook 点,格式为 `<category>:<name>`.

hook 点函数参数格式为 `/sys/kernel/debug/tracing/events/<category>/<name>/format`

按照以下方式定义 hook 函数.

```c
SEC("tp/<category>/<name>")
int function(void *ctx)
{
        return 0;
}
```


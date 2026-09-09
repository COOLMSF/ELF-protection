# ELF-protection

## `vm_embed_packer.c`（自包含 ELF 输出）

这是你描述的方案：输入可以是标准 x86_64 ELF，输出也是一个可直接执行的 ELF。packer 将运行时 stub、加密 payload 和容器头拼成一个文件；运行时由输出文件自身完成解密并执行，不需要外部 loader。

```sh
cc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
  -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
  -Wl,-z,relro,-z,now vm_embedded_stub.c -o vm_embedded_stub -lcrypto
cc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
  vm_embed_packer.c -o vm_embed_packer -lcrypto

export VM_PACKER_PASSWORD='use-a-long-random-secret'
./vm_embed_packer ./vm_embedded_stub ./helloworld ./helloworld.protected
./helloworld.protected
```

`helloworld` 可以是标准动态链接或 PIE x86_64 ELF；原文件不会被修改。输出文件前部是运行时 stub，尾部是加密 payload。严格来说 stub 就是“内部 loader”，但用户运行输出文件时不再需要额外程序。软件方式不能阻止有权限的调试器在运行时观察解密后的代码。

## `vm_packer.c`

`vm_packer.c` 是一个面向 Ubuntu 24.04 x86_64 的单文件 ELF 加密打包器。它把输入 ELF 放进加密容器，运行时由受限 VM 调度：解密后的 payload 只写入匿名 `memfd`，然后通过 `fexecve(2)` 执行，不创建明文临时 ELF 文件。

它可以防止普通的静态查看和直接 `strings`/`readelf` 读取输入 payload，但不能提供“绝对不可见”：程序运行时必须存在明文代码，拥有 root、ptrace、调试器或内核级权限的攻击者仍可能从进程内存、系统调用或执行流中恢复它。不要把它当作 DRM、密钥保护或对抗有权限逆向的方案。

安全边界：

- AES-256-GCM 加密，密钥由环境变量密码通过 PBKDF2-HMAC-SHA256 派生；
- salt、nonce、认证 tag 保存在容器头部，密码不嵌入输出文件；
- 固定 VM 指令序列：解密 → ELF 校验 → memfd 执行；
- 输入限制为 little-endian x86_64 ELF64，最大 payload 256 MiB；
- payload 只在匿名内存中短暂出现，并通过 `fexecve` 执行；
- 不包含反调试、注入、持久化、网络控制或删除原文件逻辑。

### 构建

```sh
cc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
  -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
  -Wl,-z,relro,-z,now vm_packer.c -o vm_packer -lcrypto
```

### 使用

```sh
export VM_PACKER_PASSWORD='use-a-long-random-secret'
./vm_packer pack ./input.elf ./protected.vmp
./vm_packer run ./protected.vmp
./vm_packer run ./protected.vmp arg1 arg2
```

输出容器不是可直接执行的 ELF；`protected.vmp` 不应提交到公开仓库。建议为密码使用外部 secret manager 或受限的服务环境变量，而不是写入脚本或命令历史。

## `vm_secure_elf.c`

保留的 `vm_secure_elf.c` 是一个不加载外部 payload 的 VM 示例，用于演示固定指令集、边界检查、步数限制和完整性校验。

# ELF-protection

本项目提供 ELF 静态保护和自包含打包实验代码。当前可用的自包含方案位于 `vm_embed/`：输入一个标准 x86_64 ELF，输出一个仍然可以直接执行的 ELF。输出文件内部包含运行时 stub、加密 payload 和解码执行逻辑，因此运行时不需要额外的外部 loader。

## 当前目录

```text
vm_embed/
├── vm_embedded_stub.c   # 被编译进最终输出 ELF 的运行时 stub
├── vm_embed_packer.c    # 将标准 ELF 加密并追加到 stub 的打包器
└── build_and_run.sh     # Ubuntu/Linux 构建命令示例
```

仓库中还保留了一些早期 ELF section 操作示例：

- `elfscure.c`
- `stripx.c`
- `zero_section_header.c`
- `zero_shstrndx_64.c`
- `zero_shstrndx_disk.c`
- `zero_shstrndx_mem.c`

这些文件不是当前自包含 VM 打包流程的一部分。它们会直接修改 ELF 元数据，使用前应复制备份并在测试文件上验证。

## 自包含 ELF 打包

### 1. 准备依赖

Ubuntu 24.04：

```sh
sudo apt-get install build-essential libssl-dev
```

### 2. 编译

进入 `vm_embed/` 目录：

```sh
cd vm_embed

cc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
  -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
  -Wl,-z,relro,-z,now \
  vm_embedded_stub.c -o vm_embedded_stub -lcrypto

cc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
  vm_embed_packer.c -o vm_embed_packer -lcrypto
```

也可以运行：

```sh
./build_and_run.sh
```

脚本默认使用当前目录下的 `helloworld` 作为输入。如果文件不存在，请手动执行编译命令，或把脚本中的输入路径改成实际 ELF 文件。

### 3. 打包标准 ELF

```sh
export VM_PACKER_PASSWORD='use-a-long-random-secret'

./vm_embed_packer \
  ./vm_embedded_stub \
  ./helloworld \
  ./helloworld.protected
```

参数顺序为：

```text
vm_embed_packer <runtime-stub> <input-elf> <output-elf>
```

### 4. 直接运行输出文件

```sh
./helloworld.protected
./helloworld.protected arg1 arg2
```

`helloworld.protected` 本身是 ELF，可直接交给 Linux 内核执行，不需要运行 `vm_packer run` 或其他外部 loader。原始输入文件不会被修改，输出文件以新文件方式创建。

## 工作原理

```text
标准 input ELF
      │
      ▼
vm_embed_packer
      │  AES-256-GCM 加密 payload
      │  追加 package header
      ▼
可直接执行的 output ELF
      │
      ▼
内置 runtime stub
      │  从 /proc/self/exe 读取尾部 payload
      │  PBKDF2-HMAC-SHA256 派生密钥
      │  AES-256-GCM 解密并认证
      │  写入匿名 memfd
      │  fexecve 执行原始 ELF
      ▼
原始程序行为
```

严格来说，runtime stub 就是内部 loader；区别在于它已经被打进最终 ELF，用户无需单独提供 loader。

## 支持范围和安全边界

- 当前目标平台：Linux x86_64；
- 输入格式：little-endian ELF64，`ET_EXEC` 或 `ET_DYN`；
- 支持动态链接 ELF 和 PIE ELF；
- payload 上限：256 MiB；
- 加密：AES-256-GCM；
- 密钥：由 `VM_PACKER_PASSWORD` 通过 PBKDF2-HMAC-SHA256 派生；
- 密码不会写入输出 ELF；
- 原始明文 payload 不写入普通临时文件；
- 输出采用 PIE、栈保护、FORTIFY、RELRO 和立即绑定构建；
- 不包含反调试、代码注入、持久化、网络控制或删除原文件逻辑。

该方案主要隐藏磁盘上的静态 payload，不能保证运行时绝对不可见。程序执行时必须在内存中出现可执行内容，拥有 root、ptrace、调试器或内核级权限的攻击者仍可能恢复它。不要将它当作 DRM、密钥保护或对抗高权限逆向的方案。

## 密码和输出文件注意事项

不要把密码写入公开脚本、Git 仓库或命令历史。生产环境应通过 secret manager、受限服务环境变量或其他安全凭据机制提供密码。不要提交 `*.protected` 文件到公开仓库。

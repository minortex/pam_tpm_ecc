# pam_tpm_ecc

用 TPM 2.0 持久化 ECC 密钥做 challenge-response 认证的 PAM 模块。

> Warning: This project is for experimentation only, not for production environments.

## 功能

- Rust PAM module，安装后模块名仍为 `pam_tpm_ecc.so`
- TPM 2.0 ECDSA/P-256 签名认证
- 支持 TPM key auth value，也支持空 PIN 的 key
- 公钥文件使用 `open` 后 `fstat` 校验，避免 TOCTOU
- PIN、challenge、signature 使用 `mlock` 尝试锁页，并在释放时 zeroize
- release 构建启用 LTO、`panic = abort`、Full RELRO / BIND_NOW

## 项目结构

```
pam_tpm_ecc
├── Cargo.toml
├── Cargo.lock
├── PKGBUILD
├── src/
│   ├── lib.rs              # PAM 入口和认证主流程
│   ├── args.rs             # PAM 参数解析
│   ├── pubkey.rs           # 公钥文件校验和 PEM 解析
│   ├── crypto.rs           # challenge、SHA-256、P-256 ECDSA 验签
│   ├── tpm.rs              # tss-esapi TPM 签名封装
│   ├── secure.rs           # mlock + zeroize 缓冲区
│   └── bin/tpm_sign_test.rs
└── test/
    ├── README.md
    ├── test.sh                         # 兼容入口，转发到硬件集成测试
    ├── lib/common.sh                   # 测试公共函数
    └── integration/
        ├── hardware.sh                 # 真实 TPM / 已配置 TCTI 集成测试
        └── ibmswtpm2.sh                # IBM TPM simulator + tpm2-abrmd 集成测试
```

## 构建安装

### Arch Linux

```sh
makepkg -si
```

`PKGBUILD` 会安装：

- `/usr/lib/security/pam_tpm_ecc.so`
- `/usr/bin/tpm_sign_test`
- `/usr/share/doc/pam_tpm_ecc/README.md`

### 手动安装

构建依赖：

- `cargo`
- `pkgconf`
- `tpm2-tss >= 4.0`
- `pam`

```sh
cargo build --release --locked
sudo install -Dm755 target/release/libpam_tpm_ecc.so /usr/lib/security/pam_tpm_ecc.so
sudo install -Dm755 target/release/tpm_sign_test /usr/bin/tpm_sign_test
```

## TPM 密钥

创建 ECC primary key：

```sh
tpm2_createprimary -C o -G ecc -c ecc_primary.ctx
```

创建 ECDSA/P-256 签名对象：

```sh
tpm2_create \
  -C ecc_primary.ctx \
  -G ecc256:ecdsa \
  -u ecc.pub \
  -r ecc.priv \
  -p 123456
```

加载并持久化：

```sh
tpm2_load -C ecc_primary.ctx -u ecc.pub -r ecc.priv -c ecc.ctx
sudo tpm2_evictcontrol -C o -c ecc.ctx 0x81020000
```

导出 PEM 公钥示例：

```sh
tpm2_readpublic -c 0x81020000 -f pem -o /tmp/tpm-ecc.pub.pem
sudo install -o root -g root -m 0644 /tmp/tpm-ecc.pub.pem /etc/tpm-ecc.pub.pem
```

公钥文件必须是普通文件、root 拥有，并且权限不能比 `0644` 更宽。

多用户环境建议把公钥放在 `/etc/security/pam_tpm_ecc/keys/` 下，文件名使用
`<username>.pem`：

```sh
sudo install -d -o root -g root -m 0755 /etc/security/pam_tpm_ecc/keys
sudo install -o root -g root -m 0644 /tmp/tpm-ecc.pub.pem /etc/security/pam_tpm_ecc/keys/alice.pem
```

## PAM 配置

在 `/etc/pam.d/<service>` 中添加：

```pam
auth sufficient pam_tpm_ecc.so key_handle=0x81020000 pubkey=/etc/tpm-ecc.pub.pem
```

多用户环境按当前 PAM 用户查找公钥：

```pam
auth sufficient pam_tpm_ecc.so key_handle=0x81020000 pubkey_dir=/etc/security/pam_tpm_ecc/keys
```

参数：

| 参数 | 必填 | 说明 |
|---|---|---|
| `key_handle=` | 是 | TPM 持久化 ECC key handle，支持十进制或 `0x...` |
| `pubkey=` | 二选一 | 全局 P-256 SPKI PEM 公钥 |
| `pubkey_dir=` | 二选一 | 按 PAM 用户名查找 `<username>.pem` 的公钥目录 |
| `tcti=` | 否 | TCTI 字符串，默认 `device:/dev/tpmrm0` |

`pubkey=` 和 `pubkey_dir=` 互斥；同时配置会被视为模块配置错误，不会按优先级选择其中一个。
`pubkey_dir=` 模式下，用户名只允许 ASCII 字母、数字、`.`、`_`、`-`，以避免路径穿越。
对应用户的公钥文件不存在时，模块返回 `PAM_IGNORE`，PAM 会继续执行后续规则；这可以用于给
不想使用 TPM 的用户禁用本模块。

例如让已配置公钥的用户优先使用 TPM，未配置公钥的用户继续走普通密码：

```pam
auth sufficient pam_tpm_ecc.so key_handle=0x81020000 pubkey_dir=/etc/security/pam_tpm_ecc/keys
auth include system-auth
```

不指定 `tcti=` 时模块只会使用默认的 `device:/dev/tpmrm0`，不会自动 fallback 到
`tabrmd` / `tpm2-abrmd`。

直接访问 TPM 设备：

```pam
auth sufficient pam_tpm_ecc.so key_handle=0x81020000 pubkey=/etc/tpm-ecc.pub.pem tcti=device:/dev/tpmrm0
```

通过 `tpm2-abrmd` 访问 TPM，避免调用方进程直接打开 `/dev/tpmrm0`：

```pam
auth sufficient pam_tpm_ecc.so key_handle=0x81020000 pubkey=/etc/tpm-ecc.pub.pem tcti=tabrmd
```

`tabrmd` 默认使用 system D-Bus 上的 `com.intel.tss2.Tabrmd`。在支持 D-Bus
activation 的发行版配置中，第一次连接 `tabrmd` TCTI 时可能会自动启动
`tpm2-abrmd`，所以即使事先没有手动 `systemctl start tpm2-abrmd`，调用模块时也可能看到
`tpm2-abrmd` 被拉起。

## 诊断工具

```sh
tpm_sign_test 123456 0x81020000 device:/dev/tpmrm0
```

参数顺序：

```text
tpm_sign_test [PIN] [key_handle] [tcti]
```

如果 key 没有 auth value，PIN 参数传空字符串：

```sh
tpm_sign_test "" 0x81020000 device:/dev/tpmrm0
```

## 认证流程

```
parse PAM args
  -> open/fstat/read root-owned public key PEM
  -> prompt PIN through PAM conversation
  -> mlock PIN/challenge/signature buffers
  -> generate 32-byte challenge
  -> SHA256(challenge)
  -> initialize tss-esapi context and TPM startup
  -> TR_FromTPMPublic(key_handle)
  -> TR_SetAuth(PIN)
  -> Sign(SHA256(challenge), ECDSA/SHA256, null HASHCHECK ticket)
  -> extract padded raw r||s
  -> verify original challenge with p256 ECDSA/SHA-256
  -> PAM_SUCCESS or PAM_AUTH_ERR
```

TPM 签名输入是 `SHA256(challenge)`；验证时对原始 `challenge` 做 ECDSA/SHA-256 验签，两边最终验证的是同一个 digest。

## 测试

单元测试不需要 TPM：

```sh
cargo test
```

构建 release PAM 模块：

```sh
cargo build --release --locked
```

真实 TPM 集成测试需要 TPM、`tpm2-tools`、`openssl`，PAM 端到端测试还需要
`pamtester` 和 root 权限：

```sh
sudo KEY_HANDLE=0x81020000 \
  PUBKEY=/etc/tpm-ecc.pub.pem \
  TCTI=device:/dev/tpmrm0 \
  test/integration/hardware.sh 123456
```

CI/CD 可以使用 IBM TPM 2.0 simulator。脚本会启动 `tpm_server`，默认通过 session D-Bus
启动 `tpm2-abrmd`，创建临时 ECC 签名 key，并通过 `tabrmd:bus_type=session` 运行集成测试：

```sh
test/integration/ibmswtpm2.sh 123456
```

如果 CI 环境不想经过 `tpm2-abrmd`，也可以直接使用 simulator 的 `mssim` TCTI：

```sh
SIM_USE_ABRMD=0 \
  TEST_TCTI=mssim:host=127.0.0.1,port=2321 \
  test/integration/ibmswtpm2.sh 123456
```

检查导出符号：

```sh
nm -D target/release/libpam_tpm_ecc.so | grep pam_sm_
```

检查安全属性：

```sh
readelf -d target/release/libpam_tpm_ecc.so | grep BIND_NOW
readelf -l target/release/libpam_tpm_ecc.so | grep -A1 GNU_STACK
```

## polkit

polkit helper 通常在隔离环境中运行。如果使用默认的 `device:/dev/tpmrm0`，需要显式允许
helper 访问 TPM 设备：

```sh
systemctl edit polkit-agent-helper@
```

```ini
[Service]
DeviceAllow=/dev/tpmrm0 rw
BindPaths=/dev/tpmrm0
```

如果 PAM 配置改用 `tcti=tabrmd`，helper 不需要直接访问 `/dev/tpmrm0`；TPM 设备访问由
`tpm2-abrmd` 进程完成。此时需要确保 `tpm2-abrmd` 可通过 system D-Bus 启动或已经运行。

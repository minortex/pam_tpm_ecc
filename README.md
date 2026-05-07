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
└── test/test.sh            # 集成测试脚本
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

## PAM 配置

在 `/etc/pam.d/<service>` 中添加：

```pam
auth sufficient pam_tpm_ecc.so key_handle=0x81020000 pubkey=/etc/tpm-ecc.pub.pem
```

参数：

| 参数 | 必填 | 说明 |
|---|---|---|
| `key_handle=` | 是 | TPM 持久化 ECC key handle，支持十进制或 `0x...` |
| `pubkey=` | 是 | 对应 P-256 SPKI PEM 公钥 |
| `tcti=` | 否 | TCTI 字符串，默认 `device:/dev/tpmrm0` |

带自定义 TCTI：

```pam
auth sufficient pam_tpm_ecc.so key_handle=0x81020000 pubkey=/etc/tpm-ecc.pub.pem tcti=device:/dev/tpmrm0
```

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

集成测试需要 TPM、`tpm2-tools`、`openssl`，PAM 端到端测试还需要 `pamtester`：

```sh
sudo test/test.sh 123456
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

polkit helper 通常在隔离环境中运行，需要显式允许访问 TPM 设备：

```sh
systemctl edit polkit-agent-helper@
```

```ini
[Service]
DeviceAllow=/dev/tpmrm0 rw
BindPaths=/dev/tpmrm0
```

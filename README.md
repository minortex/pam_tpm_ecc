# pam_tpm_ecc — TPM ECDSA PAM 认证模块

用 TPM 持久化 ECC 密钥做 challenge-response 认证的 PAM 模块。
用 C 语言重写 `pam_tpm_ecc.sh`，全程内存安全，通过 TSS2 ESYS API 直连 TPM，
不再依赖外部命令，无临时文件。

## 目录结构

```
c/
├── CMakeLists.txt           # 顶层 CMake
├── src/
│   ├── CMakeLists.txt       # pam_tpm_ecc.so target
│   └── pam_tpm_ecc.c        # PAM 模块源码 (~500 行)
├── test/
│   ├── CMakeLists.txt       # test_verify + tpm_sign_test targets
│   ├── test_verify.c        # 纯 OpenSSL 单元测试 (5 用例, 无 TPM)
│   ├── tpm_sign_test.c      # ESYS 签名独立诊断程序
│   └── test.sh              # 集成测试脚本 (TPM + PAM + 安全属性)
├── build/                   # CMake 输出 (gitignored)
└── README.md                # 本文档
```

## 编译

```sh
cd /home/texsd/Workdir/tpm/c
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

产物：
- `build/src/pam_tpm_ecc.so` — PAM 模块
- `build/test/test_verify` — 单元测试
- `build/test/tpm_sign_test` — ESYS 诊断工具

**依赖：** `cmake >= 3.16` `tpm2-tss >= 4.0` `openssl >= 1.1` `libpam` `pkg-config`

## 安装

```sh
cmake --install build --prefix /
# 或分步：
cmake --install build --prefix /usr      # GNU/Linux 风格
cmake --install build --prefix /usr/local  # BSD 风格
```

产物安装到 `<prefix>/lib/security/pam_tpm_ecc.so`。

## PAM 配置

在 `/etc/pam.d/<service>` 中添加：

```
auth sufficient pam_tpm_ecc.so key_handle=0x81020001 pubkey=/home/texsd/Workdir/tpm/pub.pem
```

### 参数

| 参数 | 必填 | 说明 |
|---|---|---|
| `key_handle=` | 是 | TPM 持久化 ECC 密钥句柄，支 16/10 进制 |
| `pubkey=` | 是 | ECC P-256 公钥 PEM 文件路径 |
| `tcti=` | 否 | TCTI 设备字符串，默认 `device:/dev/tpmrm0` |

### 示例

```sh
# sudo 使用 TPM 认证
# /etc/pam.d/sudo:
auth sufficient pam_tpm_ecc.so key_handle=0x81020001 pubkey=/path/to/pub.pem
auth required   pam_unix.so
```

## 认证流程

```
PAM 弹出 "TPM PIN:" 提示
  → 用户输入 PIN，mlock 锁定内存页，永不写入磁盘
  → OpenSSL RAND_bytes 生成 32 字节随机 challenge
  → SHA256(challenge) 预哈希
  → ESYS API 与 TPM 直连：tctildr → Esys_Initialize → Startup
  → Esys_TR_FromTPMPublic 获取持久化密钥句柄
  → Esys_TR_SetAuth 传入 PIN
  → Esys_Sign 对 SHA256 哈希做 ECDSA 签名
  → 提取 raw r||s，填充到 32+32 字节
  → 转换为 DER 编码
  → OpenSSL EVP_DigestVerify 验证签名
  → PAM_SUCCESS / PAM_AUTH_ERR
```

全程无临时文件，敏感数据 (PIN、challenge、签名) 在释放前 `sec_zero` 强制清零并 `munlock` 解锁。

## 内存安全设计

| 措施 | 说明 |
|---|---|
| `mlock` / `munlock` | PIN、challenge、签名三块缓冲区锁页在物理内存，禁止交换到磁盘 |
| `sec_zero` | `volatile` 屏障强制清零，编译器无法优化掉 |
| bounds check | 所有 `memcpy` 操作前检查目标缓冲区大小 |
| 无危险函数 | 零 `strcpy` / `sprintf` / `gets`，只用 `memcpy`、`strncmp`、`strnlen`、`strtoul` |
| 编译加固 | `-fstack-protector-strong` `-D_FORTIFY_SOURCE=2` `-Wl,-z,relro,-z,now` |
| 错误路径 | 任何步骤失败 → 统一 `goto cleanup` 标签 → 清零解锁释放 → 返回错误码 |
| `explicit_bzero` | PIN 从 PAM conversation 获取后立即清零原始缓冲区 |

## 关键技术决策

### 为什么用 ESYS API 而非调用外部命令

| | Shell 脚本 | C + ESYS |
|---|---|---|
| 临时文件 | mktemp 生成 challenge/sig 文件 | 纯内存操作 |
| PIN 安全 | 匿名管道，无法 mlock | mlock 锁页 + sec_zero |
| 子进程 | fork + exec tpm2_sign + openssl | 进程内直连 TPM |
| 错误处理 | `|| exit 1`，无细粒度日志 | 每个 TSS2/OpenSSL 调用都有 syslog 日志 |
| 依赖 | bash、tpm2-tools、openssl CLI | 仅动态库 |

### tpm2-tss 4.x null validation ticket 的坑

在 tpm2-tss 4.x 中，`Esys_Sign` 的 `validation` 参数不能传 `NULL`（会触发
`TSS2_RESMGR_RC_BAD_REFERENCE`），必须传一个构造好的 ticket：

```c
TPMT_TK_HASHCHECK null_ticket = {
    .tag       = TPM2_ST_HASHCHECK,
    .hierarchy = TPM2_RH_NULL
};
```

但更关键的是：带 null ticket 时，**TPM 把 digest 当作已哈希数据直接签名**，不再做二次哈希。
因此必须自己用 `SHA256(challenge)` 预哈希，再把 32 字节哈希值传给 `Esys_Sign`。

tpm2-tools 的做法相同：先调 `tpm2_hash` 拿到 SHA256 哈希 + 真实验证票据，再传哈希给 Sign。

## 测试

### 运行

```sh
# 单元测试 (无需 TPM)
ctest --test-dir build -R unit
# 或直接运行
./build/test/test_verify

# 集成测试 (TPM sign + OpenSSL verify + PAM 符号 + 安全属性)
test/test.sh <TPM_PIN>

# 完整集成测试 (含 pamtester 端到端 PAM 认证)
sudo test/test.sh <TPM_PIN>
```

### 测试结果 (全部 20 项通过)

```
=== pam_tpm_ecc Integration Tests ===

[1] Environment checks
  PASS  TPM device present
  PASS  TPM responds
  PASS  pubkey PEM exists

[2] PAM module symbols
  PASS  .so exists
  PASS    exported: pam_sm_authenticate
  PASS    exported: pam_sm_setcred
  PASS    exported: pam_sm_acct_mgmt
  PASS    exported: pam_sm_open_session
  PASS    exported: pam_sm_close_session
  PASS    exported: pam_sm_chauthtok

[3] TPM sign + OpenSSL verify
  PASS  TPM sign (with PIN)
  PASS  OpenSSL verify
  PASS  wrong challenge → rejected
  PASS  corrupted signature → rejected

[4] PAM module end-to-end (pamtester)
  PASS  PAM service config created
  PASS  pamtester authenticate
  PASS  wrong PIN → rejected by PAM module

[5] Shared library health
  PASS  all shared library dependencies resolved
  PASS  GNU_STACK: no-execute (NX)
  PASS  Full RELRO (BIND_NOW)

────────────────────────────────
Results: 20 passed
```

### C 单元测试 (5/5)

```
raw r||s → DER → verify roundtrip         PASS
wrong challenge → verify fails             PASS
corrupted signature → verify fails         PASS
r component w/ leading zero → still valid  PASS
non-existent PEM file → BIO_new_file fails PASS
```

## 调试

日志写入 syslog：

```sh
journalctl -f -t pamtester | grep pam_tpm
```

模块在各失败点都会记录具体的 `TSS2_RC` / OpenSSL 错误码。

## 前置条件

1. TPM 2.0 物理设备或模拟器
2. 持久化的非受限 ECC P-256 签名密钥 (`tpm2_create` + `tpm2_evictcontrol`)
3. 对应公钥导出为 X.509 SubjectPublicKeyInfo PEM 格式

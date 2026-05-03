# Maintainer: minortex <texsd dot tt29 at outlook com>
pkgname=pam_tpm_ecc-git
pkgver=0.0.1+r9.1b8df91
pkgrel=1
pkgdesc="PAM module for TPM2 ECC authentication"
arch=('x86_64' 'aarch64')
url="https://github.com/minortex/pam_tpm_ecc"
license=('LGPL')
depends=(
  'tpm2-tss>=4.0'
  'openssl>=1.1'
  'pam'
)
makedepends=(
  'cmake>=3.16'
  'pkg-config'
  'git'
)
provides=("pam_tpm_ecc")
conflicts=("pam_tpm_ecc")
source=("${pkgname}::git+${url}.git")
sha256sums=('SKIP')

pkgver() {
  cd "${srcdir}/${pkgname}"
  printf "0.0.1+r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
  cd ${srcdir}/${pkgname}
  # 修复 $srcdir 引用警告：将源码绝对路径映射为 "."
  export CFLAGS+=" -ffile-prefix-map=${srcdir}=."

  # 使用 -Wno-dev 减少 CMake 自身的警告
  cmake -B build -S . \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -Wno-dev
  cmake --build build
}

package() {
  cd ${srcdir}/${pkgname}
  DESTDIR="${pkgdir}" cmake --install build
}

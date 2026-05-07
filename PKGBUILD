# Maintainer: minortex <texsd dot tt29 at outlook com>
pkgname=pam_tpm_ecc-git
pkgver=0.1.0.r10.gcd6939b
pkgrel=1
pkgdesc="PAM module for TPM2 ECC authentication"
arch=('x86_64' 'aarch64')
url="https://github.com/minortex/pam_tpm_ecc"
license=('LGPL-2.1-only')
depends=(
  'gcc-libs'
  'glibc'
  'tpm2-tss>=4.0'
  'pam'
)
makedepends=(
  'cargo'
  'pkgconf'
  'git'
)
provides=("pam_tpm_ecc")
conflicts=("pam_tpm_ecc")
source=("${pkgname}::git+${url}.git")
sha256sums=('SKIP')

pkgver() {
  cd "${srcdir}/${pkgname}"
  printf "0.1.0.r%s.g%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

prepare() {
  cd "${srcdir}/${pkgname}"
  cargo fetch --locked
}

build() {
  cd "${srcdir}/${pkgname}"
  cargo build --release --frozen
}

package() {
  cd "${srcdir}/${pkgname}"
  install -Dm755 target/release/libpam_tpm_ecc.so \
    "${pkgdir}/usr/lib/security/pam_tpm_ecc.so"
  install -Dm755 target/release/tpm_sign_test \
    "${pkgdir}/usr/bin/tpm_sign_test"
  install -Dm644 README.md "${pkgdir}/usr/share/doc/pam_tpm_ecc/README.md"
}

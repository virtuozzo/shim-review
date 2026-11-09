# Reproducible build of the Virtuozzo shim 16.1 (x86_64).
# Base image and package repositories are pinned: almalinux:10.1 by digest, packages from the frozen 10.1 vault.
FROM almalinux:10.1@sha256:5e1f19a1fc018dcb17f042411bff68c64cb06131ff1a71356d0be011f87c7baa AS build
RUN rm -f /etc/yum.repos.d/*.repo
COPY vault.repo /etc/yum.repos.d/vault.repo
WORKDIR /root
RUN dnf -y install rpm-build dnf-plugins-core
COPY rpmmacros /root/.rpmmacros
COPY shim-unsigned-x64-16.1-1.vl10.src.rpm /root/
RUN rpm -ivh shim-unsigned-x64-16.1-1.vl10.src.rpm
RUN dnf builddep -y /builddir/build/SPECS/shim-unsigned-x64.spec
RUN rpm -q gcc binutils glibc-devel elfutils-libelf-devel openssl-devel pesign make
RUN rpmbuild -bb /builddir/build/SPECS/shim-unsigned-x64.spec
RUN rpm2cpio /builddir/build/RPMS/x86_64/shim-unsigned-x64-16.1-1.vl10.x86_64.rpm | cpio -diu

FROM build AS verify
COPY shimx64.efi /
RUN ls -l /*.efi ./usr/share/shim/16.1-1.vl10/x64/shim*.efi
RUN hexdump -Cv ./usr/share/shim/16.1-1.vl10/x64/shimx64.efi > built-x64.hex
RUN hexdump -Cv /shimx64.efi > orig-x64.hex
RUN objdump -h ./usr/share/shim/16.1-1.vl10/x64/shimx64.efi
RUN diff -u orig-x64.hex built-x64.hex
RUN pesign -h -P -i ./usr/share/shim/16.1-1.vl10/x64/shimx64.efi
RUN pesign -h -P -i /shimx64.efi
RUN sha256sum ./usr/share/shim/16.1-1.vl10/x64/shimx64.efi /shimx64.efi

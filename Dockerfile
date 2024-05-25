FROM almalinux:9.3
RUN whoami

WORKDIR /root
RUN dnf -y install rpm-build dnf-plugins-core
COPY rpmmacros /root/.rpmmacros
COPY shim-unsigned-x64-15.8-4.vl9.src.rpm /root/
RUN rpm -ivh shim-unsigned-x64-15.8-4.vl9.src.rpm
RUN sed -i 's/linux32 -B/linux32/g' /builddir/build/SPECS/shim-unsigned-x64.spec
RUN dnf builddep -y --enablerepo=crb /builddir/build/SPECS/shim-unsigned-x64.spec
RUN rpmbuild -bb /builddir/build/SPECS/shim-unsigned-x64.spec
COPY shimx64.efi /
RUN rpm2cpio /builddir/build/RPMS/x86_64/shim-unsigned-x64-15.8-4.vl9.x86_64.rpm | cpio -diu
RUN ls -l /*.efi ./usr/share/shim/15.8-4.vl9/*/shim*.efi
RUN hexdump -Cv ./usr/share/shim/15.8-4.vl9/x64/shimx64.efi > built-x64.hex
RUN hexdump -Cv /shimx64.efi > orig-x64.hex
RUN objdump -h ./usr/share/shim/15.8-4.vl9/x64/shimx64.efi
RUN diff -u orig-x64.hex built-x64.hex
RUN pesign -h -P -i ./usr/share/shim/15.8-4.vl9/x64/shimx64.efi
RUN pesign -h -P -i /shimx64.efi
RUN sha256sum ./usr/share/shim/15.8-4.vl9/x64/shimx64.efi /shimx64.efi
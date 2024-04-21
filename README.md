This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

Check the docs directory in this repo for guidance on submission and
getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
Virtuozzo Research https://www.virtuozzo.com/

*******************************************************************************
### What product or service is this for?
*******************************************************************************
Virtuozzo Hybrid Server is a bare-metal virtualization solution that includes system container virtualization, KVM-based virtual machines, software-defined storage and simplified hosting management. 

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
As UEFI Secure Boot is more and more often considered mandatory feature of hardware, it is critical for Bare Metal Solutions to support the UEFI Secure Boot. Since we are enabling the massive hosting providers and Alternative Clouds, it is important to be secure and compliant. 

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
We are using our custom kernel which enables some essential features for our products which is not provided by any other company. 

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: Artem Vasiliev
- Position: Build Systems TeamLead
- Email address: artem.vasiliev@virtuozzo.com
- PGP key fingerprint: AFE5 4587 9350 6517 6FFC 67C6 2D9D 190B CF62 D8C3 (https://keys.openpgp.org/vks/v1/by-fingerprint/AFE54587935065176FFC67C62D9D190BCF62D8C3)

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Denis Lunev
- Position: Virtualisation Development TeamLead
- Email address: den@openvz.org
- PGP key fingerprint: F6F1 367F 707C F915 1922 7CAD 3F30 A5AE 9377 9C9F (https://keys.openpgp.org/vks/v1/by-fingerprint/F6F1367F707CF91519227CAD3F30A5AE93779C9F)

*******************************************************************************
### Were these binaries created from the 15.8 shim release tar?
Please create your shim binaries starting with the 15.8 shim release tar file: https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.8 and contains the appropriate gnu-efi source.

*******************************************************************************
Yes

*******************************************************************************
### URL for a repo that contains the exact code which was built to get this binary:
*******************************************************************************
https://github.com/rhboot/shim/tree/15.8
Src RPM attached

*******************************************************************************
### What patches are being applied and why:
*******************************************************************************
No patches applied.

*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
No, we don't set the NX bit.

*******************************************************************************
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
*******************************************************************************
RHEL Like

*******************************************************************************
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of GRUB2 affected by any of the CVEs in the July 2020, the March 2021, the June 7th 2022, the November 15th 2022, or 3rd of October 2023 GRUB2 CVE list, have fixes for all these CVEs been applied?

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************
We are using the the same code as RHEL and those were mitigated by RHEL already.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
The entry should look similar to: `grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`
*******************************************************************************
Same source code as RHEL

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
*******************************************************************************
No previous submissions were made

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
*******************************************************************************
Yes all 3

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
Yes, the main intention of the patches - provide the high density virtualisation. Support of system containers(OpenVZ), Perfomance optimization for Virtuozzo solutions.

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
Yes

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We don't use the vendor_db functionality.

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
We don't use vendor_dbx in this build. No previous CA certificates were submitted. 

*******************************************************************************
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
*******************************************************************************
Any RHEL9.0 like OS.
The Dockerfile in this repository can be used to launch an identical buildroot with Almalinux9.

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
root.log and build.log in this repo.

*******************************************************************************
### What changes were made in the distro's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..
*******************************************************************************
None, no previous SHIM signed.

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
e2ef9c8e9b589630a83c0ff2a827e3d7ebc4d664165e640744f1e23fea464aab  shimx64.efi

*******************************************************************************
### How do you manage and protect the keys used in your SHIM?
*******************************************************************************
Those are stored in protected centralized storage in Hashicorp Vault.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the SHIM?
*******************************************************************************
None

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, UKI(s), shim + all child shim binaries )?
### Please provide exact SBAT entries for all shim binaries as well as all SBAT binaries that shim will directly boot.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
If you are using a downstream implementation of GRUB2 or systemd-boot (e.g.
from Fedora or Debian), please preserve the SBAT entry from those distributions
and only append your own. More information on how SBAT works can be found
[here](https://github.com/rhboot/shim/blob/main/SBAT.md).
*******************************************************************************
shim:
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.virtuozzo,1,Virtuozzo,shim,15.8,security@virtuozzo.com

grub2:
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,3,Free Software Foundation,grub,2.02,https//www.gnu.org/software/grub/
grub.rh,2,Red Hat,grub2,2.06-70.el9,mailto:secalert@redhat.com
grub.virtuozzo,1,Virtuozzo,grub2,2.06-70.vl9,mailto:security@virtuozzo.com

fwupd:
sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
fwupd-efi,1,Firmware update daemon,fwupd-efi,1.4,https://github.com/fwupd/fwupd
fwupd-efi.rhel,1,Red Hat Enterprise Linux,fwupd,1.8.16,mail:secalert@redhat.com
fwupd-efi.virtuozzo,1,Virtuozzo,fwupd,1.8.16,mail:security@virtuozzo.com

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
*******************************************************************************
all_video boot blscfg cat configfile cryptodisk echo ext2 f2fs fat font gcry_rijndael gcry_rsa gcry_serpent gcry_sha256 gcry_twofish gcry_whirlpool gfxmenu gfxterm gzio halt http increment iso9660 jpeg loadenv loopback linux lvm luks luks2 mdraid09 mdraid1x minicmd net normal part_apple part_msdos part_gpt password_pbkdf2 pgp png reboot regexp search search_fs_uuid search_fs_file search_label serial sleep syslinuxcfg test tftp version video xfs zstd efi_netfs efifwsetup efinet lsefi lsefimmap connectefi backtrace chain tpm usb usbserial_common usbserial_pl2303 usbserial_ftdi usbserial_usbdebug keylayouts at_keyboard

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
No arm64 or riscv fork in the distro.

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
RHEL 9 downstream, grub2-2.06-70.el9.2

*******************************************************************************
### If your SHIM launches any other components, please provide further details on what is launched.
*******************************************************************************
Shim launches only GRUB, no other components.

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
GRUB will launch only linux kernel, no other components. However we are kkeping in mind probable necessity in future to use fwupd for firmware updates. 

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
*******************************************************************************
All the standard builtin checks.

*******************************************************************************
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB2)?
*******************************************************************************
No.
*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
Currently it is current RHEL 9.3 based kernel-5.14.0-425.vz9. With all recent patches included. 

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
Not sure there is exists any. However please don't hesitate to contact in need.

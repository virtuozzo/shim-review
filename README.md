This repo is for review of requests for signing shim. To create a request for review:

- clone this repo (preferably fork it)
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push it to GitHub
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

As of 27 June 2026, shims sent to Microsoft can only be signed by the Microsoft UEFI CA 2023. It is no longer possible to get your shim signed by the "old" Microsoft Corporation UEFI CA 2011 key. Up-to-date information from Microsoft about Secure Boot can be found here: https://support.microsoft.com/en-US/servicing/os/secure-boot/2026/02/updates-and-announcements

New signing requirements have also taken effect, and are available here: https://techcommunity.microsoft.com/blog/hardware-dev-center/updated-microsoft-uefi-signing-requirements/1062916 Please note that undergoing this shim review exempts you from yearly security audits, as long as your shim only hands off to open source boot loaders.

Hint: check the [docs](./docs/) directory in this repo for guidance on submission and getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
Organization name and website:  
Virtuozzo International GmbH, https://www.virtuozzo.com/

*******************************************************************************
### What's the legal data that proves the organization's genuineness?
The reviewers should be able to easily verify, that your organization is a legal entity, to prevent abuse.
Provide the information, which can prove the genuineness with certainty.
*******************************************************************************
Company/tax register entries or equivalent:  
(a link to the organization entry in your jurisdiction's register will do)  

Swiss commercial register (Zefix): Virtuozzo International GmbH, UID CHE-274.027.033, seat Schaffhausen  
https://www.zefix.ch/en/search/entity/list/firm/1286290

The public details of both your organization and the issuer in the EV certificate used for signing .cab files at Microsoft Hardware Dev Center File Signing Services.  
(**not** the CA certificate embedded in your shim binary)

Example:

```
Issuer: O=MyIssuer, Ltd., CN=MyIssuer EV Code Signing CA
Subject: C=XX, O=MyCompany, Inc., CN=MyCompany, Inc.
```

```
Issuer: C=GB, O=Sectigo Limited, CN=Sectigo Public Code Signing CA EV R36
Subject: serialNumber=CHE-274.027.033, jurisdictionC=CH, businessCategory=Private Organization, C=CH, ST=Schaffhausen, O=Virtuozzo International GmbH, CN=Virtuozzo International GmbH
```

*******************************************************************************
### What product or service is this for?
*******************************************************************************
Virtuozzo Infrastructure 8.x (formerly Virtuozzo Hybrid Infrastructure): a bare-metal hyperconverged platform (KVM virtualization, software-defined storage, networking) installed on customers' and service providers' servers. Version 8.x is built on Virtuozzo Linux 10, a RHEL 10 rebuild with our own kernel.

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
The product is installed on bare-metal servers owned by hosting providers and enterprises, where UEFI Secure Boot is more and more often a mandatory policy. These servers trust the Microsoft UEFI CA, so our boot chain has to start from a Microsoft-signed shim. Our previous shim (review #406) is signed by the Microsoft UEFI CA 2011, which is being phased out; new machines only trust the Microsoft UEFI CA 2023.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
We ship our own kernel (OpenVZ/Virtuozzo patches for system containers and high-density virtualization) that is not signed by any other vendor, so no other distro's shim would boot it.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
Please upload the PGP keys to a well-known keyserver like keyserver.ubuntu.com and/or include them in the review as an .asc file, and point to them here.

*******************************************************************************
- Name: Artem Vasiliev
- Position: Build Systems Team Lead
- Email address: artem.vasiliev@virtuozzo.com
- PGP key fingerprint: AFE5 4587 9350 6517 6FFC 67C6 2D9D 190B CF62 D8C3
- File/keyserver location: https://keyserver.ubuntu.com/pks/lookup?search=AFE54587935065176FFC67C62D9D190BCF62D8C3&fingerprint=on&op=index

Same contact and key as in the last verification (review #406); cross-signed with the secondary contact.

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Denis V. Lunev
- Position: Virtualization Development Team Lead, co-founder (OpenVZ is our open-source project)
- Email address: den@openvz.org
- PGP key fingerprint: 0BAE AA87 D302 0ADC 1150 E51F 5E07 71B6 CB66 6CAB
- File/keyserver location: https://keyserver.ubuntu.com/pks/lookup?search=0BAEAA87D3020ADC1150E51F5E0771B6CB666CAB&fingerprint=on&op=index

Same contact and key as in the last verification (review #406); cross-signed with the primary contact.

*******************************************************************************
### Were these binaries created from the 16.1 shim release tar?
Please create your shim binaries starting with the 16.1 shim release tar file: https://github.com/rhboot/shim/releases/download/16.1/shim-16.1.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/16.1 and contains the appropriate gnu-efi source.

Make sure the tarball is correct by verifying your download's checksum
(SHA256, SHA512) with the following ones:

```
46319cd228d8f2c06c744241c0f342412329a7c630436fce7f82cf6936b1d603  shim-16.1.tar.bz2
ca5f80e82f3b80b622028f03ef23105c98ee1b6a25f52a59c823080a3202dd4b9962266489296e99f955eb92e36ce13e0b1d57f688350006bba45f2718f159fb  shim-16.1.tar.bz2
```

Make sure that you've verified that your build process uses that file
as a source of truth (excluding external patches) and its checksum
matches. You can also further validate the release by checking the PGP
signature: there's [a detached
signature](https://github.com/rhboot/shim/releases/download/16.1/shim-16.1.tar.bz2.asc)

The release is signed by the maintainer Peter Jones - his master key
has the fingerprint `B00B48BC731AA8840FED9FB0EED266B70F4FEF10` and the
signing sub-key in the signature here has the fingerprint
`02093E0D19DDE0F7DFFBB53C1FD3F540256A1372`. A copy of his public key
is included here for reference:
[pjones.asc](https://github.com/rhboot/shim-review/blob/main/pjones.asc)

Once you're sure that the tarball you are using is correct and
authentic, please confirm this here with a simple *yes*.

A short guide on verifying public keys and signatures should be available in the [docs](./docs/) directory.
*******************************************************************************
Yes. The source RPM in this repo contains the unmodified release tarball:
```
46319cd228d8f2c06c744241c0f342412329a7c630436fce7f82cf6936b1d603  shim-16.1.tar.bz2
```

*******************************************************************************
### URL for a repo that contains the exact code which was built to result in your binary:
Hint: If you attach all the patches and modifications that are being used to your application, you can point to the URL of your application here (*`https://github.com/YOUR_ORGANIZATION/shim-review`*).

You can also point to your custom git servers, where the code is hosted.
*******************************************************************************
https://github.com/virtuozzo/shim-review (this repo: `shim-unsigned-x64-16.1-1.vl10.src.rpm` and `Dockerfile`)  
Upstream: https://github.com/rhboot/shim/tree/16.1

*******************************************************************************
### What patches are being applied and why:
Mention all the external patches and build process modifications, which are used during your building process, that make your shim binary be the exact one that you posted as part of this application.
*******************************************************************************
No patches to shim. Build settings only (see the spec in the SRPM):
- `VENDOR_CERT_FILE=secureboot-ca-x86_64.cer` (our new CA, DER)
- `data/sbat.virtuozzo.csv` with our vendor SBAT entry
- `ENABLE_SHIM_HASH=true`, `SBAT_AUTOMATIC_DATE=2023012900` (as in RHEL 10). We keep this level on purpose. Our older product lines boot through the previous shim with a `grub,3` GRUB: 7.x uses grub2-2.06-80.vl9.2, and 8.0/8.1 use grub2-2.12-14.vl10.pth1. The SbatLevel that a shim writes to NVRAM persists, and the previous shim enforces it too. A higher automatic level, such as upstream's default `2024040900` with `grub,4`, would therefore stop a server that has once run this shim from booting the install or rescue media of those lines, or from rolling back to them. Our new chain carries `grub,5` (see the SBAT section), so the latest level `2025051000` (`shim,4`, `grub,5`) can be applied through `SbatPolicy` without breaking it. We will raise the automatic level in a later shim once those lines are out of support.
- `EFIDIR=virtuozzo`, `DEFAULT_LOADER=\\grubx64.efi`
- `COMMIT_ID=afc49558b34548644c1cd0ad1b6526a9470182ed` (the 16.1 tag)

*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
No, the NX bit is not set (`DllCharacteristics 0`).

*******************************************************************************
### What exact implementation of Secure Boot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
Skip this, if you're not using GRUB2.
*******************************************************************************
Downstream RHEL 10 implementation (Virtuozzo Linux 10 rebuild of the RHEL 10 grub2 package).

*******************************************************************************
### Do you have fixes for all the following GRUB2 CVEs applied?
**Skip this, if you're not using GRUB2, otherwise make sure these are present and confirm with _yes_.**

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
* February 2025
  * Details: https://lists.gnu.org/archive/html/grub-devel/2025-02/msg00024.html, SBAT increase to 5
  * CVE-2024-45774
  * CVE-2024-45775
  * CVE-2024-45776
  * CVE-2024-45777
  * CVE-2024-45778
  * CVE-2024-45779
  * CVE-2024-45780
  * CVE-2024-45781
  * CVE-2024-45782
  * CVE-2024-45783
  * CVE-2025-0622
  * CVE-2025-0624
  * CVE-2025-0677
  * CVE-2025-0678
  * CVE-2025-0684
  * CVE-2025-0685
  * CVE-2025-0686
  * CVE-2025-0689
  * CVE-2025-0690
  * CVE-2025-1118
  * CVE-2025-1125
*******************************************************************************
Yes. Our grub2 is the RHEL 10 grub2-2.12-46 source package rebuilt without changes to the Secure Boot code, so all the listed fixes are present (it carries `grub,5`). Our only extra patches are three cosmetic graphics patches, attached: `vl-1002-gfx-terminal-background.patch`, `vl-1003-gfx-cut-long-titles-using-ellipsis.patch`, `vl-1004-Support-showing-UEFI-logo-when-booting-in-UEFI.patch`.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 5?
Skip this, if you're not using GRUB2, otherwise do you have an entry in your GRUB2 binary similar to:  
`grub,5,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`?
*******************************************************************************
Yes:
```
grub,5,Free Software Foundation,grub,2.12,https//www.gnu.org/software/grub/
```

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
If you had no previous signed shim, say so here. Otherwise a simple _yes_ will do.
*******************************************************************************
Our previous shim (review #406, shim 15.8) embeds our old CA. Its Authenticode SHA-256, the value for DBX, is `0dd5f6989b44a647663f4ae135bb44cd21d606179eb226b9decf74d62f8b0cb9`; the file SHA-256 is `fa7866274689d8cec54380183e6ebf46fa79c14bf39f4f88c6169a6c9de7834c`. The 7.x, 8.0 and 8.1 lines still boot through that shim, so revoking it now would make supported customer servers unbootable. We will send the Authenticode hash to Microsoft for DBX when the last of those lines reaches end of life. Until then the GRUB and kernel signing keys issued from the old CA remain usable, but only for those lines. They are kept in the same YubiHSM 2 FIPS as non-exportable keys (see the key protection section).  
Yes: the new shim embeds only the new CA, so it cannot boot any GRUB2 build signed under the old CA.

Until the old shim is in DBX, the GRUB2 builds already signed for the older lines matter. Under Secure Boot they can only use the modules built into the signed image. We checked those modules against the fixes behind `grub,4` (ntfs) and `grub,5` (February 2025):

- **8.0 / 8.1, grub2-2.12-14.vl10.pth1** (RHEL 10.0 based): it carries the February 2025 fixes. Among them are both gettext integer overflows and the fixes in commands/extcmd, kern/dl, commands/pgp, commands/read, minicmd (`dump` under lockdown) and the jpeg reader. It also carries "fs: Disable many filesystems under lockdown", which covers the `squash4` and `hfsplus` modules in its image, and the ntfs fixes.
- **7.x, grub2-2.06-80.vl9.2** (RHEL 9.4 based): it carries the ntfs fixes, but `ntfs` is not in its image. It does **not** carry the February 2025 fixes, and some of the affected modules are in its image (`gettext`, `extcmd`, `jpeg`, `net`, `pgp`, `minicmd`). We are rebuilding the 7.x GRUB2 with these fixes, signed with the 7.x GRUB key in the HSM, and will ship it as an update of the 7.x line. We will post here when it is published.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
Hint: upstream kernels should have all these applied, but if you ship your own heavily-modified older kernel version, that is being maintained separately from upstream, this may not be the case.  
If you are shipping an older kernel, double-check your sources; maybe you do not have all the patches, but ship a configuration, that does not expose the issue(s).
*******************************************************************************
Yes, all three. Our kernel is based on the RHEL 10 6.12 kernel (6.12.0-211.52.1.22.x.vz10), which contains them.

*******************************************************************************
### How does your signed kernel enforce lockdown when your system runs with Secure Boot enabled?
Hint: If it does not, we are not likely to sign your shim.
*******************************************************************************
`CONFIG_SECURITY_LOCKDOWN_LSM=y`, `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y`, `CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y`: the kernel enters integrity lockdown automatically when booted with Secure Boot enabled (RHEL behaviour).

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
Yes. The patches add OpenVZ/Virtuozzo system containers (resource isolation, checkpoint/restore), high-density virtualization and performance features for our products. They do not touch the lockdown, module signature, kexec or EFI Secure Boot code of the RHEL kernel.

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
Yes. Every kernel build generates a new module signing key (`CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"`, created during the build and discarded afterwards); modules of two different builds carry different signing key IDs.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We don't use vendor_db; a single CA certificate is embedded via `VENDOR_CERT_FILE`.

*******************************************************************************
### If you are re-using the CA certificate from your last shim binary, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs mentioned earlier to vendor_dbx in shim. Please describe your strategy.
This ensures that your new shim+GRUB2 can no longer chainload those older GRUB2 binaries with issues.

If this is your first application or you're using a new CA certificate, please say so here.
*******************************************************************************
We are using a **new** CA certificate (`Virtuozzo Secure Boot CA 2026`); the CA from review #406 is not embedded, so vendor_dbx is not needed.

*******************************************************************************
### Is the Dockerfile in your repository the recipe for reproducing the building of your shim binary?
A reviewer should always be able to run `docker build .` to get the exact binary you attached in your application.

Hint: Prefer using *frozen* packages for your toolchain, since an update to GCC, binutils, gnu-efi may result in building a shim binary with a different checksum.

If your shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case, what the differences would be and what build environment (OS and toolchain) is being used to reproduce this build? In this case please write a detailed guide, how to setup this build environment from scratch.
*******************************************************************************
Yes. `docker build .` rebuilds `shimx64.efi` and compares it byte for byte with the attached binary.
The toolchain is frozen: the base image is pinned by digest (`almalinux:10.1@sha256:5e1f19a1fc018dcb17f042411bff68c64cb06131ff1a71356d0be011f87c7baa`) and all packages come from the AlmaLinux 10.1 vault (10.1 is superseded by 10.2, so the vault no longer changes). Toolchain used:
```
gcc-14.3.1-2.1.el10.alma.1.x86_64
binutils-2.41-58.el10_1.2.alma.1.x86_64
glibc-devel-2.39-58.el10_1.7.alma.1.x86_64
elfutils-libelf-devel-0.193-1.el10.x86_64
openssl-devel-3.5.1-7.el10_1.alma.1.x86_64
pesign-116-6.el10.alma.1.x86_64
make-4.4.1-9.el10.x86_64
```

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
`build.log`: the full `docker build` output (buildroot creation, builddep, rpmbuild, comparison with the attached binary).

*******************************************************************************
### What changes were made in the distro's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..

Skip this, if this is your first application for having shim signed.
*******************************************************************************
- shim 15.8 → 16.1.
- **New CA** `Virtuozzo Secure Boot CA 2026`, RSA-4096, generated inside a YubiHSM 2 FIPS in FIPS mode (see the key protection answer). The CA used in review #406 is retired.
- New GRUB2 and kernel signing certificates issued from the new CA (CA:FALSE, EKU codeSigning only).
- Distro base moved from Virtuozzo Linux 9 (RHEL 9) to Virtuozzo Linux 10 (RHEL 10): grub2 2.06 → 2.12 (SBAT grub,5), kernel 5.14 → 6.12.
- No UKI, no systemd-boot.

*******************************************************************************
### What is the SHA256 hash of your final shim binary?
*******************************************************************************
```
e0af797310b2137f026b498972796effcf1eb516e20a0e14b8f5463351d4e6db  shimx64.efi
```

*******************************************************************************
### How do you manage and protect the keys used in your shim?
Describe the security strategy that is used for key protection. This can range from using hardware tokens like HSMs or Smartcards, air-gapped vaults, physical safes to other good practices.
*******************************************************************************
- **CA key**: generated on 2026-11-09 inside a YubiHSM 2 FIPS (FIPS 140-2 Level 3) with FIPS mode enabled, in a recorded ceremony. The key has never existed outside the HSM; it can only be exported wrapped under an HSM wrap key, for a backup to a second YubiHSM 2 FIPS. The factory authentication key was deleted; there are two named administrator authentication keys (the two security contacts), each with its own password kept only in that person's password manager. The CA key is in its own HSM domain and is used only to issue signing certificates.
- **GRUB2 / kernel signing keys**: two separate RSA-4096 keys generated inside the same HSM, non-exportable, in a different HSM domain (`Virtuozzo Secure Boot GRUB Signing 2026`, `Virtuozzo Secure Boot Kernel Signing 2026`; CA:FALSE, EKU codeSigning only). The signing builder uses them through a dedicated sign-only authentication key limited to that domain, so it cannot use the CA key.
- The HSM is attached to a server in an access-controlled data center; only the Build Systems team has access to the host.
- **Previous CA (review #406)**: the private key of the previous CA is damaged and no longer exists, so no new certificates can be issued from it. That CA is retired: it is not embedded in this shim, and we will ask Microsoft to add the old shim to DBX. The GRUB/kernel signing keys issued from it are kept only to maintain our legacy 7.x, 8.0 and 8.1 lines (still on the old shim) until their end of life; they are not trusted by this shim. These keys are kept in the same YubiHSM 2 FIPS (signing domain, sign-only, not exportable) and are used through the same signing service.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the shim?
A _yes_ or _no_ will do. There's no penalty for the latter.
*******************************************************************************
No.

*******************************************************************************
### Are you embedding a CA certificate in your shim?
A _yes_ or _no_ will do. There's no penalty for the latter. However,
if _yes_: does that certificate include the X509v3 Basic Constraints
to say that it is a CA? See the [docs](./docs/) for more guidance
about this.
*******************************************************************************
Yes. It has `X509v3 Basic Constraints: critical, CA:TRUE, pathlen:0` and `X509v3 Key Usage: critical, Certificate Sign, CRL Sign`.

*******************************************************************************
### What certificates are embedded in your shim, and what are their key types and sizes?
For each certificate embedded in your shim, state whether it is newly
embedded in your shim or reused unchanged from your last accepted shim.
For each certificate in your shim, provide its algorithm
and key size.

Certificates newly embedded in your shim must use an RSA key with a modulus
of at least 4096 bits. Existing vendors reusing a certificate unchanged
are not required to replace it, but are strongly encouraged to replace
smaller RSA keys with 4096-bit or larger keys when they have an
appropriate opportunity to do so.
*******************************************************************************
One certificate, **newly embedded**: `secureboot-ca-x86_64.cer`
- Subject: `C=CH, ST=Zurich, L=Zurich, O=Virtuozzo International GmbH, CN=Virtuozzo Secure Boot CA 2026, emailAddress=security@virtuozzo.com`
- RSA 4096, sha256WithRSAEncryption, valid 2026-11-09 → 2046-11-09
- SHA256 fingerprint: `3F:86:26:38:E3:8C:6F:BF:4E:64:4D:5A:18:7E:30:A8:82:A6:A8:3F:D7:34:9B:23:2C:57:9F:4B:AA:7C:B0:2C`

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide the exact SBAT entries for all binaries you are booting directly through shim.
Hint: The history of SBAT and more information on how it works can be found [here](https://github.com/rhboot/shim/blob/main/SBAT.md). That document is large, so for just some examples check out [SBAT.example.md](https://github.com/rhboot/shim/blob/main/SBAT.example.md)

If you are using a downstream implementation of GRUB2 (e.g. from Fedora or Debian), make sure you have their SBAT entries preserved and that you **append** your own (don't replace theirs) to simplify revocation.

**Remember to post the entries of all the binaries. Apart from your bootloader, you may also be shipping e.g. a firmware updater, which will also have these.**

Hint: run `objcopy --dump-section .sbat=/dev/stdout YOUR_EFI_BINARY` to get these entries. Paste them here. Preferably surround each listing with three backticks (\`\`\`), so they render well.
*******************************************************************************
shim:
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.virtuozzo,1,Virtuozzo,shim,16.1,mailto:security@virtuozzo.com
```
grub2 (grub2-2.12-46.vl10.pth1):
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,5,Free Software Foundation,grub,2.12,https//www.gnu.org/software/grub/
grub.rh,2,Red Hat,grub2,2.12-46.vl10,mailto:secalert@redhat.com
grub.virtuozzo,1,Virtuozzo,grub2,2.12-46.vl10.pth1,mail:security@virtuozzo.com
grub.centos,2,Red Hat,grub2,2.12-46.vl10.pth1,mailto:secalert@redhat.com
```
The `mail:` scheme in our `grub.virtuozzo` entry is a typo in our grub2 spec and has been there since our first SBAT GRUB. It will be `mailto:` in the next grub2 build. SBAT does not parse the URL field, so this does not affect revocation.

fwupd-efi is not signed and is not booted through shim.

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
Skip this, if you're not using GRUB2.

Hint: this is about those modules that are in the binary itself, not the `.mod` files in your filesystem.
*******************************************************************************
all_video boot blscfg blsuki cat configfile cryptodisk echo ext2 f2fs fat font gcry_rijndael gcry_rsa gcry_serpent gcry_sha256 gcry_twofish gcry_whirlpool gfxmenu gfxterm gzio halt hfsplus http increment iso9660 jpeg loadenv loopback linux lvm luks luks2 memdisk mdraid09 mdraid1x minicmd net normal part_apple part_msdos part_gpt password_pbkdf2 pgp png reboot regexp search search_fs_uuid search_fs_file search_label serial sleep squash4 syslinuxcfg test tftp version video xfs zstd efi_netfs efifwsetup efinet lsefi lsefimmap connectefi backtrace chain tpm usb usbserial_common usbserial_pl2303 usbserial_ftdi usbserial_usbdebug keylayouts at_keyboard

(the RHEL 10 grub2 list, unchanged)

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
Not applicable: x86_64 only, no systemd-boot.

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
RHEL 10 downstream grub2, rebuilt as grub2-2.12-46.vl10.pth1 (upstream 2.12 + RHEL 10 patches + the three cosmetic Virtuozzo graphics patches attached to this repo).

*******************************************************************************
### If your shim launches any other components apart from your bootloader, please provide further details on what is launched.
Hint: The most common case here will be a firmware updater like fwupd.
*******************************************************************************
None. shim launches only GRUB2 (plus MokManager and fallback from this same shim build).

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
Skip this, if you're not using GRUB2 or systemd-boot.
*******************************************************************************
GRUB2 launches only the Linux kernel.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
Summarize in one or two sentences, how your secure bootchain works on higher level.
*******************************************************************************
shim verifies GRUB2 against our CA; GRUB2 verifies the kernel through the shim_lock protocol; the kernel enforces lockdown under Secure Boot and only loads modules signed with its per-build ephemeral key.

*******************************************************************************
### Does your shim load any loaders that support loading unsigned kernels (e.g. certain GRUB2 configurations)?
*******************************************************************************
No.

*******************************************************************************
### What kernel are you using? Which patches and configuration does it include to enforce Secure Boot?
*******************************************************************************
kernel-6.12.0-211.52.1.22.x.vz10: the RHEL 10 6.12 kernel plus Virtuozzo patches, with the RHEL Secure Boot configuration: `CONFIG_SECURITY_LOCKDOWN_LSM=y`, `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y`, `CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y`, `CONFIG_MODULE_SIG=y`, `CONFIG_MODULE_SIG_ALL=y`, `CONFIG_INTEGRITY_PLATFORM_KEYRING=y`, `CONFIG_LOAD_UEFI_KEYS=y`, `CONFIG_IMA_ARCH_POLICY=y`.

*******************************************************************************
### What contributions have you made to help us review the applications of other applicants?
The reviewing process is meant to be a peer-review effort and the best way to have your application reviewed faster is to help with reviewing others. We are in most cases volunteers working on this venue in our free time, rather than being employed and paid to review the applications during our business hours. 

A reasonable timeframe of waiting for a review can reach 2-3 months. Helping us is the best way to shorten this period. The more help we get, the faster and the smoother things will go.

For newcomers, the applications labeled as [*easy to review*](https://github.com/rhboot/shim-review/issues?q=is%3Aopen+is%3Aissue+label%3A%22easy+to+review%22) are recommended to start the contribution process.
*******************************************************************************
Community review of OpenText ZENworks shim 16.1: https://github.com/rhboot/shim-review/issues/594#issuecomment-6744641545  
Community review of Parted Magic shim 16.1: https://github.com/rhboot/shim-review/issues/588#issuecomment-6744747745

*******************************************************************************
### Add any additional information you think we may need to validate this shim signing application.
*******************************************************************************
Previous accepted review: https://github.com/rhboot/shim-review/issues/406 (tag `virtuozzo-shim-x86_64-20240401`).  
This application moves our product to the Microsoft UEFI CA 2023 and replaces our CA with a new HSM-backed one.

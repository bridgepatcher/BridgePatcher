# Release checksums

The SHA256 checksum of every file attached to a [release](https://github.com/bridgepatcher/BridgePatcher/releases),
recorded automatically by a GitHub Actions workflow when the file is uploaded.

Checksums are only ever **added** to this file, never changed or removed. If a file on a
release is replaced later, its first checksum stays here and the new one is added below
it with a warning. The file's git history shows when each checksum was recorded, which a
replaced file can't change. `SHA256SUMS` on a release, in comparison, is regenerated
whenever the release's files change.

## How to check a download

On macOS, in Terminal:

```sh
shasum -a 256 ~/Downloads/<file>
```

The output must match the checksum listed below for that release and file. If it
doesn't, or if the file is marked as changed below and you didn't expect that, don't
open it and [report it](https://github.com/bridgepatcher/BridgePatcher/security/advisories/new).

To check every file of a release at once, copy its lines into a file named `sums.txt`
next to the downloads and run `shasum -a 256 -c sums.txt`.

<!-- releases (newest first) -->

<!-- release: 4.0.0.2000004.6.0.0.1 -->
## 4.0.0.2000004.6.0.0.1 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.6.0.0.1) · published 2026-11-27

Recorded 2026-11-27 14:59 EET (UTC+2):

```
6bc1d9706dbb5f38c478898d9e6143db8fdbda2fe3ff4abc44fbfaff1b2e8cf9  AutoPkg-Assets.pkg
85ec01f1dff53345334bdc0a36ce65c84d875dda066eac19316bd4e67f677427  BridgePatcher-Uninstaller.pkg
4c5ba16f32c82ce89e01a854fcafdc0dcedf2c8e22d3726469f56f98f6721db4  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.5 -->
## 4.0.0.2000004.5

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.5) · published 2026-11-26

Recorded 2026-11-27 00:07 EET (UTC+2):

```
0b8aa7213e8d79258cb19951fe0b7b22e7d9946ab4bbdbdd9cd7f6fcac743704  AutoPkg-Assets.pkg
e2fbb1839af89377dab9311c430bafc6121c731b8c69323a9c9fe9d34bc800e6  BridgePatcher-Uninstaller.pkg
c9c05bc27b638e710d34ab7a0ab42f3ff1f222e203df7abb9ad7d50f63b689ec  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.4 -->
## 4.0.0.2000004.4

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.4) · published 2026-11-26

Recorded 2026-11-26 14:58 EET (UTC+2):

```
3e65660c9cfd3fc4423311514098a2f90a5bee1f08452db5b115a8339fef13e8  AutoPkg-Assets.pkg
f7337a369fa189e5ef1a129cb8b975d4744a497677c400ec5028307ca2175f89  BridgePatcher-Uninstaller.pkg
8327f6945dfc6e3c9825048f1670d67485d4f7ff0e160777e6f35995567c7dee  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.3 -->
## 4.0.0.2000004.3

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.3) · published 2026-11-25

Recorded 2026-11-25 11:37 EET (UTC+2):

```
1ca7da50ceeecc85d316a40e7b6192fda1ee8b72e43519f427d3c5c2a96b58c7  AutoPkg-Assets.pkg
8958d255b116cbf115a5d4d4a8077a931db58a117b118495fe977aff45e28411  BridgePatcher-Uninstaller.pkg
f5b60b16db126ca87ce883fc31c7259bd382ecbfeabbd8c87a728455c06aa61d  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.2 -->
## 4.0.0.2000004.2

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.2) · published 2026-11-25

Recorded 2026-11-25 00:35 EET (UTC+2):

```
5887ea4b7ce86bf232ee51e05b95b5f90509d7c41e6b7da67c4bb6f84363ef56  AutoPkg-Assets.pkg
cb1aa72d27dfabc6e833efa627014309265c32c2f41fe4bc835f8a0e0231dd7a  BridgePatcher-Uninstaller.pkg
e91f8f13042e2fef9907b0461350e3b578391ade5809d80572fc135dad58d045  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.1 -->
## 4.0.0.2000004.1

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.1) · published 2026-11-24

Recorded 2026-11-24 23:08 EET (UTC+2):

```
cace7b346a446dcee3eb8c17d9e2332c6a416ff0bbe136a963abe089e2a71d52  AutoPkg-Assets.pkg
0f1e354f0945bba4cd382986fb1ea42de39d2fe535e6d56920616af56bca6ac5  BridgePatcher-Uninstaller.pkg
71cc8ba09dfae45b83c2ac132db5d19280b5df932a5afee2129ec5089428ee78  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.0.0.8 -->
## 4.0.0.2000004.0.0.8 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.0.0.8) · published 2026-11-23

Recorded 2026-11-24 00:06 EET (UTC+2):

```
ae4cfc4a826475338e7903bf751953ccebbbe95041e4b68ca151a05c60b8a29d  AutoPkg-Assets.pkg
d80ece44d458a8ef5893be692b598c3f666011a13895d48f1c3c1d4914398383  BridgePatcher-Uninstaller.pkg
93fcbc1b38eaaaaef336a4f0daa3032a8e4cdf6ee31a1092dcf9a76e31491e15  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.0.0.7 -->
## 4.0.0.2000004.0.0.7 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.0.0.7) · published 2026-11-23

Recorded 2026-11-23 01:03 EET (UTC+2):

```
9978d2b8053d7fbedce95869b57034f7e55306fbc09b0888936d2cad392dadca  AutoPkg-Assets.pkg
bec64cc5a8b932773ee6710c169687fc4c96e9df06c761058cc5e6fe1fd2ac5b  BridgePatcher-Uninstaller.pkg
4f00d51a57bc8bb736c684949f99a4ad36e74f1f58739e63c8ceff3cb787353a  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000003.8.1 -->
## 4.0.0.2000003.8.1

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000003.8.1) · published 2026-11-23

Recorded 2026-11-23 00:21 EET (UTC+2):

```
c15ebc77a190885fa3190d02ee1b949559493501133efd6bb4e5f9d2118ecb43  AutoPkg-Assets.pkg
1c184e0f143e2058d068dc8180d1fd72919d3d9d96296327867aa512a10986c2  BridgePatcher-Uninstaller.pkg
aab21b5e5be5de2f351879beba6a385433706d1efeeef0750b6f211aa0d24f5c  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.0.0.6 -->
## 4.0.0.2000004.0.0.6 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.0.0.6) · published 2026-11-22

Recorded 2026-11-22 14:04 EET (UTC+2):

```
637f86c5963733a7a0d7c217bc112eb2a6e84d2484b6bf86b00211c041244045  AutoPkg-Assets.pkg
d8487e29a3e10b94c5a15f6ebc0027ecf199acc2699fddf7a78e901ff1b4da67  BridgePatcher-Uninstaller.pkg
97bdcc15db2d805206c3024e946674760a6d73959fc7fba3806e61f8d922c40c  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.0.0.5 -->
## 4.0.0.2000004.0.0.5 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.0.0.5) · published 2026-11-22

Recorded 2026-11-22 05:53 EET (UTC+2):

```
162fac73a129ff415f5515a836a1c01a01c6d8be1c099eaa4b7f1e813bd1a1a9  AutoPkg-Assets.pkg
790bdf7fc7eefcfafe3ba53b6671e70d69cee1f7ae2ef8e1730094641bd6e8ed  BridgePatcher-Uninstaller.pkg
4d2f6f80ba691e6fe86ebb6d6109e3f14bfcf2469dd71422f4a0785dee3c4bad  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.0.0.4 -->
## 4.0.0.2000004.0.0.4 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.0.0.4) · published 2026-11-21

Recorded 2026-11-21 19:02 EET (UTC+2):

```
aa62c9ef064d74734f114ecc9f68f600a7b361f4d4f4f6ba23de9cc6562ed9ed  AutoPkg-Assets.pkg
5f482a4ae7a6bb1676a99de200de5a355f2f8ec85a9db505e5aecb8e212cbe3c  BridgePatcher-Uninstaller.pkg
d8bf2e586e26ad10064c2d850fbefe8df6915ab645cdb1dc863d94c29fe6fb06  BridgePatcher.pkg
```

> [!WARNING]
> Changed after its checksum was first recorded, recorded 2026-11-21 19:19 EET (UTC+2). The first checksum of each file is the one listed above.

```
8afdf1273805ac0cfbe0d48e73b995276794367d79f5dea980c3b3561bbcf760  AutoPkg-Assets.pkg
53e1bbb089ec44af2459e74ad3d8d3f63abf973cd41aae72c7756bf97920515e  BridgePatcher-Uninstaller.pkg
b764105ce893295adc8507495db2a809fca0ab9dcb1fe865c138c699ca81374b  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000003.8 -->
## 4.0.0.2000003.8

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000003.8) · published 2026-11-21

Recorded 2026-11-21 18:51 EET (UTC+2):

```
dbf7513866908e98da72d556d027eb9c471c3568e79d7313e91a3e0255f5193f  AutoPkg-Assets.pkg
ff1686bbbef62b328a26a04260813ef06797c08bdc562ad9f6cebe46d53843fd  BridgePatcher-Uninstaller.pkg
d8527e34d99906d857aac03c1372868d431aa95e8273975453fb50887808c710  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.0.0.3 -->
## 4.0.0.2000004.0.0.3 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.0.0.3) · published 2026-11-21

Recorded 2026-11-21 17:39 EET (UTC+2):

```
72232ac10d1ed720323d211572e662d7af650f2d0690d1753c2dcfea8c47e19b  AutoPkg-Assets.pkg
461c10977767891efd51583ee5517ebbd72bf0ec5bdf496a65e8ee583f9fd152  BridgePatcher-Uninstaller.pkg
f2ab60ceb8f3aca1393cae634b36992f5126b18988a9fba4b83d0b56e4770669  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.0.0.2 -->
## 4.0.0.2000004.0.0.2 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.0.0.2) · published 2026-11-21

Recorded 2026-11-21 14:36 EET (UTC+2):

```
8e4e23af03b624b3bdcbbfb234491ec5c8711cee30f7a6284b25307d48f2a3c0  AutoPkg-Assets.pkg
d0bb22455ee1c8d58b45ee99653f35604286c60d3376a2a79e3c079622960d38  BridgePatcher-Uninstaller.pkg
5d492fd7ee3a6392aa92f19326dcffd8761523004cdffe66d01bef2e26a34401  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004.0.0.1 -->
## 4.0.0.2000004.0.0.1 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004.0.0.1) · published 2026-11-21

Recorded 2026-11-21 13:44 EET (UTC+2):

```
8f4758aeaa6e82c819d0880066faa0bffdfde0d96cf7358e21afd52622db98d6  AutoPkg-Assets.pkg
fd4b2cf0dee4c16ddd66a3cc79ca91caf58610588a763718c1efdd5e06fdfa3d  BridgePatcher-Uninstaller.pkg
8b1b0896c1688a5bfd3e05f8e2fb9b39c78c279110d47fc4ba3a95b85fe0de23  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000004 -->
## 4.0.0.2000004 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000004) · published 2026-11-20

Recorded 2026-11-21 13:44 EET (UTC+2):

```
11a3ee9285a68a555cce0506ca203ad4c87ac70b1e8707c697e8a702688a914f  AutoPkg-Assets.pkg
40719f88acb929c62f261bdbe4572158a2efe063e147def0ea0ba0914203093d  BridgePatcher-Uninstaller.pkg
f8a7dff22a41c565d86be29fe19bd2e7c9deff1f9925d6c9aceb509381810e63  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000003.7.1 -->
## 4.0.0.2000003.7.1 (pre-release)

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000003.7.1) · published 2026-11-18

Recorded 2026-11-21 13:44 EET (UTC+2):

```
b15e6a5e818b709b9527e5cd6c97aea37d2d481a14829e352dabd07d438edf0f  AutoPkg-Assets.pkg
1c549dae49e437435a89f48c2722801895a3af3b8456a420c9155ee43d977546  BridgePatcher-Uninstaller.pkg
aea4d3c6a3a4aba4e527257828eb6634cd2ca33341ef8ac96be161cabd95024c  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000003.7 -->
## 4.0.0.2000003.7

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000003.7) · published 2026-11-21

Recorded 2026-11-21 13:36 EET (UTC+2):

```
817deb75d34b2a661a46cbf98c78833e3f74463a28ae9fa41cd84824ea8f86e0  AutoPkg-Assets.pkg
44fe8063dce741697670b71ff5792e8a6a4e1d3e90b0852760a25c082b153baa  BridgePatcher-Uninstaller.pkg
0e520ec8f5c3d016ee7108da7cda6316a37ec4a83823e79651e3aaf417be5f47  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000003.6 -->
## 4.0.0.2000003.6

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000003.6) · published 2026-11-15

Recorded 2026-11-15 23:57 EET (UTC+2):

```
61218a25ea5361e4fc11383e1409b7bd399d7536c54e908583331f17db4b0edc  AutoPkg-Assets.pkg
a0b4e77ff70aa17c3bb20c50b3d9c33e7fa8684e7d5b90e43371ce86c2d6fe28  BridgePatcher-Uninstaller.pkg
fd939de7e292b51a86684d9b4471b1ee9807f761383b460cc1e2308c686e68da  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000003.5 -->
## 4.0.0.2000003.5

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000003.5) · published 2026-11-15

Recorded 2026-11-15 13:55 EET (UTC+2):

```
a4c7b0182e5ed7cd3b375d3fa69bdb789e00e5922171b49f292da0ddbeac4322  AutoPkg-Assets.pkg
a08a20e0c18e8f6ab088ac66ad64812191aaf1f9f9d60c26c8eea93c7bf8eeb9  BridgePatcher-Uninstaller.pkg
05507181ec4b558c59836360f75471e0c24113f4ebd2b79cc5c9b71e2ebbea50  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000003.4 -->
## 4.0.0.2000003.4

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000003.4) · published 2026-11-14

Recorded 2026-11-15 00:17 EET (UTC+2):

```
65b11f9c2dcd60975ca158d198c10cc3eb3e4a9e6dbe0fbbebcd07ff722be270  AutoPkg-Assets.pkg
ad064ab2d695786b574c2f490c963939724a8aa5f47ae8d8c3f2fac13106f6b6  BridgePatcher-Uninstaller.pkg
25d34818a9ca7d557e1d8b728c34c419913707a86e1e25dd0c8df398fe429539  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000003.3 -->
## 4.0.0.2000003.3

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000003.3) · published 2026-11-14

Recorded 2026-11-15 00:17 EET (UTC+2):

```
84d9ffcea969120f0a6cec5d0dbc755bf0d801d91192b0e3ccb36fe015a74c54  AutoPkg-Assets.pkg
d6c0d88aefdf965df4d35edb4952a117455d8c6727f88ec0d2d9f1f5d7b74572  BridgePatcher-Uninstaller.pkg
0f4e2359bf49c85b6036801cc01d18c6dd8ff55d5361f8d29abeb117fda5a396  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000003.2 -->
## 4.0.0.2000003.2

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000003.2) · published 2026-11-13

Recorded 2026-11-15 00:18 EET (UTC+2):

```
35fa9abfbbe77a07df136a84f4dba9932d9c3a5199b6642c24ecd4896223b390  AutoPkg-Assets.pkg
ec0e9f7edb261649ef67612b923e0a16ccf3a2ab27ebfd25f4ae14b2226d8883  BridgePatcher-Uninstaller.pkg
8d7b3ab83db7fce8cae9094ff5a5ecee5be52fd4ae4c852e21e3af1db94009c0  BridgePatcher.pkg
```

<!-- release: 4.0.0.2000003.1 -->
## 4.0.0.2000003.1

[Release page](https://github.com/bridgepatcher/BridgePatcher/releases/tag/4.0.0.2000003.1) · published 2026-11-09

Recorded 2026-11-15 00:18 EET (UTC+2):

```
4842b099b339772aadb2f629c26d4d367e7aad35c4f15625356c1ff053e96c6c  AutoPkg-Assets.pkg
beb9ecffb2aeb350e3e4cfff824336d668810c65f4117c629b9114288e3ad347  BridgePatcher-Uninstaller.pkg
f9a67e9b372ca08627f009f93ec706700b971f20fa7e5973845d7b3e2e69867f  BridgePatcher.pkg
```

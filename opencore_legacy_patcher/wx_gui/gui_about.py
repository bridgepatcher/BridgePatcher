"""
gui_about.py: About frame
"""

import wx
import wx.html2
import markdown
import re
import logging
from pathlib import Path
from .. import constants



class AboutFrame(wx.Frame):

    def __init__(self, global_constants: constants.Constants) -> None:
        if wx.FindWindowByName("About"):
            return

        logging.info("Generating About frame")
        super(AboutFrame, self).__init__(None, title="About", size=(500, 600), style=wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
        self.constants: constants.Constants = global_constants
        self.Centre()
        self.hyperlink_colour = (25, 179, 231)

        self._generate_elements(self)

        self.Show()


    def _generate_elements(self, frame: wx.Frame) -> None:

        self.webview = wx.html2.WebView.New(self)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.webview, 1, wx.EXPAND)
        self.SetSizer(sizer)

        self.load_markdown()

    def load_markdown(self):
        markdown_text = '<div align="center">\n  <h1>BridgePatcher — T1 & T2 macOS Tahoe Edition</h1>\n  <p><b>Developed & Maintained by <a href="https://github.com/albert-mueller">albert-mueller (Albert Müller)</a> in the <a href="https://github.com/bridgepatcher">bridgepatcher</a> organization, with community contributions</b></p>\n  <p><i>Restoring full graphics acceleration, Broadcom Wi-Fi, audio routing, and T1/T2 security on macOS 26 Tahoe & macOS 15 Sequoia</i></p>\n</div>\n\n---\n\n> [!CAUTION]\n> **BridgePatcher is an independent community fork and is not\n> affiliated with, maintained by, or endorsed by Dortania. Authentic releases are\n> exclusively published on GitHub:\n> [github.com/bridgepatcher/BridgePatcher/releases](https://github.com/bridgepatcher/BridgePatcher/releases).**\n> Websites that present BridgePatcher as an official Dortania product, or offer it for\n> download anywhere else, are not ours — don\'t download from them. BridgePatcher was\n> formerly called OpenCore Legacy Patcher T2 (OCLP-T2): repositories and websites that\n> still use that name are not ours either.\n> **WARNUNG!**\n> **BridgePatcher ist ein unabhängiger Community-Fork und steht in keiner\n> Verbindung zu Dortania, wird nicht von Dortania betreut oder unterstützt. Echte\n> Releases gibt es ausschließlich auf GitHub.** Seiten, die BridgePatcher als offizielles\n> Dortania-Produkt ausgeben oder woanders zum Herunterladen anbieten, gehören nicht zu\n> diesem Projekt - bitte von solchen Seiten nichts herunterladen. BridgePatcher hieß\n> früher OpenCore Legacy Patcher T2 (OCLP-T2): Repositorys und Seiten, die noch diesen\n> Namen verwenden, gehören ebenfalls nicht zu uns.\n\n> **Unofficial fork.** Please don\'t report BridgePatcher issues to Dortania.\n>\n> This product includes software developed by Dortania and OpenCore Legacy\n> Patcher contributors. See [LICENSE.txt](LICENSE.txt).\n\n### 👑 Authorship & Contributions\nThis repository is the dedicated development fork led by **albert-mueller (Albert Müller)**. While building upon work by Dortania, Acidanthera, this fork independently engineered the critical solutions that make macOS 26 Tahoe fully usable on legacy and T1/T2 hardware:\n\n1. **T1 Security & Native Login**: Engineered the Native Software Keystore login flow on macOS Tahoe for `MacBookPro14,1`, `MacBookPro14,2`, and `MacBookPro14,3` (retaining Apple ID/iCloud, resolving Keychain panics).\n2. **Broadcom Wi-Fi Restoration**: Unblocked the `IOSkywalkFamily` kernel stack in the EFI builder and root patcher on macOS 15 & 26 Tahoe, restoring full Wi-Fi functionality on Broadcom chipsets (`14E4:43BA`).\n3. **GPU Hardware Acceleration & GuC**: Injected Intel GuC firmware loading (`igfxfw=2`) and display port keepalive (`igfxonln=1`) for Kaby Lake, eliminating Tahoe UI micro-stutters.\n4. **AMD Polaris Power-Gating**: Developed the `radpg=15` and `agdpmod=pikera` patch combination for Radeon Pro 555/560 dGPUs, eliminating GPU switching lags.\n5. **AMD Legacy GCN Fix**: Resolved the missing `AMDOpenCL` import bug in root patch payloads.\n6. **Tahoe Metal Libraries**: Ported [MetallibSupportPkg](https://github.com/Medelcartelinc/MetallibSupportPkg) to macOS Tahoe (26.x) with multi-endpoint fallback.\n\n---\n\nA Python-based project revolving around [Acidanthera\'s OpenCorePkg](https://github.com/acidanthera/OpenCorePkg) and [Lilu](https://github.com/acidanthera/Lilu) for both running and unlocking features in macOS on supported and unsupported Macs.\nSecurity researchers can report vulnerabilities in the app via GitHub Security advisories.\n\n> **⚠️ On T2 Macs only, this patcher disables SIP completely to be able to boot macOS properly** What is SIP? SIP, in short for System Integrity Protection, protects against attackers from tampering with core system files. However, on T2 Macs, SIP also causes thermal throttling and other issues when booting via OpenCorePkg, so it needs to be disabled.\n\n\n> **⚠️ Building EFIs on Hackintoshes is unsupported by this patcher!** Building EFIs for Hackintoshes is unsupported by this patcher. I’ll explain clearly why: like Dortania’s OCLP, it generates EFIs for real Macs. They wouldn’t work on Hackintoshes. While BridgePatcher uses OpenCore under the hood, real Macs boot differently macOS from a Hackintosh. Also, a GIGABYTE board with let’s say, i7-8700B may offer the exact same board with different configurations, so predicting what patches are needed is infeasible on something no one does know. Also, on the same board depending on the config you may need different boot arguments. And also, it doesn’t use OpenCore’s version of boot.efi, it uses the one that works on real Macs. Standard Hackintoshes rely on BOOTx64.efi. So claiming that BridgePatcher can build EFIs for Hackintoshes just because it uses OpenCore is propaganda - it\'s true that OpenCore works on Hackintoshes, but that\'s not true for the patcher itself - it either produces EFIs for Hackintoshes or real Macs, that\'s it. It can\'t produce for both. So the release note in 4.0.0.16050 says for itself:\nfixes a vulnerability where an attacker or bad Hackintosh user could trick a Hackintosh user into building OpenCore EFIs for real Macs by spoofing the SMBIOS as a Mac computer\n>\n> **⚠️ Das Erstellen von EFIs auf Hackintoshes wird von diesem Patcher nicht unterstützt!** Das Erstellen von EFIs für Hackintoshes wird von diesem Patcher nicht unterstützt. Ich erkläre Ihnen den Grund: Wie Dortanias OCLP generiert er EFIs für echte Macs. Diese würden auf Hackintoshes nicht funktionieren. Obwohl BridgePatcher im Hintergrund OpenCore verwendet, booten echte Macs macOS anders als ein Hackintosh. Außerdem kann ein GIGABYTE-Board mit beispielsweise einem i7-8700B in verschiedenen Konfigurationen erhältlich sein. Daher ist es unmöglich vorherzusagen, welche Patches benötigt werden, wenn niemand die genaue Konfiguration kennt. Selbst auf demselben Board können je nach Konfiguration unterschiedliche Boot-Argumente erforderlich sein. Zudem verwendet er nicht die OpenCore-Version von boot.efi, sondern diejenige, die auf echten Macs funktioniert. Standard-Hackintoshes verwenden BOOTx64.efi. Die Behauptung, BridgePatcher könne EFIs für Hackintoshes erstellen, nur weil er OpenCore verwendet, ist Propaganda. Zwar funktioniert OpenCore auf Hackintoshes, aber das stimmt nicht für den Patcher selbst. Er erstellt entweder EFIs für Hackintoshes oder für echte Macs, nicht für beides. Die Versionshinweise zu 4.0.0.16050 belegen dies:\n"fixes a vulnerability where an attacker or bad Hackintosh user could trick a Hackintosh user into building OpenCore EFIs for real Macs by spoofing the SMBIOS as a Mac computer" oder auf Deutsch übersetzt - „Behebt eine Sicherheitslücke, durch die ein Angreifer oder ein Hackintosh-Nutzer einen Hackintosh-Nutzer dazu verleiten konnte, OpenCore-EFIs für echte Macs zu erstellen, indem er das SMBIOS als Mac-Computer fälschte.“\n\n> **⚠️⚠️⚠️⚠️⚠️ Warning** No support for macOS 27 Golden Gate and newer versions of macOS because macOS 27 Golden Gate and newer versions are arm64-only, so only for Apple Silicon Macs. So the answer is clear. macOS 26 Tahoe is the last supported macOS version by this project.\n\n> **⚠️⚠️⚠️⚠️⚠️ Warnung** macOS 27 Golden Gate und neuere macOS-Versionen sind nicht unterstützt, weil diese sind nur für Apple Silicon/arm64 Macs. Also die Antwort ist klar. macOS 26 Tahoe ist die letzte Version, die von dieser Projekt unterstützt wird.\n\n> **⚠️ EXPERIMENTAL FORK** — Adds **macOS 15 Sequoia and macOS 26 Tahoe support for all unsupported Macs**. T2 Macs as of now are unsupported by the official OpenCore Legacy Patcher from Dortania. Use it at your own risk. It\'s still in alpha stage, so I highly recommend to backup all your data and do it only on a spare T2 Mac to experiment. This is experimental alpha software.\n## T2 Mac Support\n\n> **💡 Recommended Download**: Always download pre-compiled releases directly from [Releases](https://github.com/bridgepatcher/BridgePatcher/releases) for guaranteed stability, bundled payloads, and proper packaging.\n\n> **🚧 Not ready for general use**\n\n> **Progress:**\n\n- [X] Installer boots\n- [X] MacBookAir8,1 and MacBookAir8,2 can boot the installer\n- [X] Internal hard drive mounts properly on T2 Macs\n- [ ] ability to reach the desktop\n- [ ] Post install - issues with second stage\n- [ ] GPU accelaration/WiFi - most T2 Macs will have GPU accelaration out of the box, and on certain T2 Macs, also WiFi\n\nOur goal of this project is to add support for T2 Macs so unsupported T2 Macs can boot into Tahoe. This project does run also on non-T2 Macs and we\'re committing to improve macOS 26 Tahoe compatability even on non-T2 Macs.\n\n### 🌟 Validated & Working Models on macOS 26 Tahoe (Standard / Safe Build)\n\nThanks to recent testing and optimizations, the following models are fully operational on macOS 26 Tahoe using the **Standard Build Profile**:\n\n* **MacBook Pro (13-inch, 2017, Two TB3 Ports) — `MacBookPro14,1`**:\n    * **Graphics**: Full hardware acceleration via Intel Iris Plus Graphics 640 (Kaby Lake GuC firmware `igfxfw=2`, zero stuttering).\n    * **Networking**: Broadcom Wi-Fi (`14E4:43BA` / AirportBrcmNIC) working via Modern Wireless root patching and unblocked Skywalk driver.\n    * **Audio & Video**: Fully functional, smooth UI rendering and media playback.\n* **MacBook Pro (15-inch, 2017) — `MacBookPro14,3`**:\n    * **Graphics**: Dual-GPU switching (Intel HD 630 + AMD Radeon Pro 555/560 with `agdpmod=pikera` & `radpg=15` power-gating fix).\n    * **Security & Auth**: T1 security chip supported with password login, Apple Account & iCloud connectivity.\n    * **Networking & Audio**: Broadcom Wi-Fi & AppleHDA / AppleALC audio (`alcid=13`).\n* **MacBook Pro (13-inch, 2017, Four TB3 Ports) — `MacBookPro14,2`**:\n    * Intel Iris Plus 650 graphics acceleration, T1 chip support, Broadcom Wi-Fi and audio.\n\n### 🧪 Work in Progress / Experimental Testing\n* **MacBook Pro (15-inch, Mid 2015) — `MacBookPro11,4 / MacBookPro11,5` (Haswell/Broadwell)**:\n    * Haswell graphics and Wi-Fi drivers are currently in active testing/development. Do not consider fully validated yet.\n \n* **Unsupported T2 Macs, such as 2018 Mac mini**\n    * requires some testing and work to get reliably to the desktop\n\nNoteworthy features of BridgePatcher:\n\n* Support for macOS Monterey, Ventura, Sonoma, Sequoia and eventually add support for Tahoe.\n* Native Over the Air (OTA) System Updates\n* Supports Penryn and newer Macs\n* Full support for WPA Wi-Fi and Personal Hotspot on BCM943224 and newer wireless chipsets\n* System Integrity Protection, FileVault 2, .im4m Secure Boot and Vaulting\n* Recovery OS, Safe Mode and Single-user Mode booting on non-native OSes\n* Unlocks features such as Sidecar and AirPlay to Mac even on native Macs\n* Enables enhanced SATA and NVMe power management on non-Apple storage devices\n* Zero firmware patching required (ie. APFS ROM patching)\n* Graphics acceleration for both Metal and non-Metal GPUs\n\n----------\n\nNote: Only clean-installs and upgrades are supported. macOS Big Sur installs already patched with other patchers, such as [Patched Sur](https://github.com/BenSova/Patched-Sur) or [bigmac](https://github.com/StarPlayrX/bigmac), cannot be used due to broken file integrity with APFS snapshots and SIP. Here\'s an exception: if you are already using patchers like OCLP-Mod or OCLP-Plus or the official OpenCore Legacy Patcher by Dortania, you can revert the root patches and upgrade to this patcher. \n\n* You can, however, reinstall macOS with this patcher and retain your original data\n\nNote 2: Currently, BridgePatcher officially supports patching to run macOS Monterey through Tahoe installs. For older OSes, OpenCore may function; however, support is currently not provided from Albert Müller.\n\n* For macOS Mojave and Catalina support, we recommend the use of [dosdude1\'s patchers](http://dosdude1.com)\n\n## Getting Started\n\nTo start using the project, please see our in-depth guide:\n\n* [BridgePatcher Guide](https://bridgepatcher.github.io/)\n\n## Support\n\nThis project is offered on an AS-IS basis, and we do not guarantee support for any issues that may arise. Community support for this independent fork is provided through [GitHub Discussions](https://github.com/bridgepatcher/BridgePatcher/discussions).\n\n## Running from source\n\nTo run the project from source, see here: [Build and run from source](./SOURCE.md)\n\n## Credits\n\n* [Acidanthera](https://github.com/Acidanthera)\n    * OpenCorePkg, as well as many of the core kexts and tools\n* [DhinakG](https://github.com/DhinakG)\n    * Main co-author\n* [Khronokernel](https://github.com/Khronokernel)\n    * Main co-author\n    * Great amounts of help with debugging, and code suggestions\n* [Ausdauersportler](https://github.com/Ausdauersportler)\n    * iMacs Metal GPUs Upgrade Patch set and documentation\n* [nxvid](https://github.com/nxvid/OpenCore-Legacy-Patcher-T2/)\n    * for documenting and fixing an issue where sbvmm might not have been injected on T2 Macs\n\n* [Matteo](https://github.com/Medelcartelinc) and [Matteo](https://github.com/matteoiacca)\n    * Adding support for T1 Macs on Tahoe\n    * writing patches for T1 and non-T1 Macs for macOS 26 Tahoe\n    * fixing some bugs, testing and documenting issues\n* [zkennedy137](https://github.com/zkennedy137)\n    * testing, documenting, and fixing issues with unsupported T2 Macs\n    * writing the Spoof-VMM kext so unsupported T2 Macs can get further at booting macOS 26 and 15 on unsupported hardware\n* [gandolf243](https://github.com/gandolf243)\n    * UI redesign\n    * fixing some bugs, testing and documenting issues\n* [DrDonk](https://github.com/DrDonk)\n    * for helping me write a valid patch for AppleKeyStore\n    * testing and troubleshooting\n* [TheRaddish1313](https://github.com/TheRaddish1313)\n    * for fixing framebuffer issues and boot args\n    * testing and troubleshooting\n* [vit9696](https://github.com/vit9696)\n* [Albert Müller](https://github.com/albert-mueller/)\n    * Adding support for unsupported T2 Macs and the main author of this fork\n    * Help troubleshooting, determining fixes, fixing security vulnerabilities and writing patches\n* [YBronst](https://github.com/YBronst/OCLP-Plus)\n    * for fixing modern wireless on macOS 26 Tahoe\n* [pyquick](https://github.com/pyquick) and [hackdoc](https://github.com/hackdoc)\n    * [improving support for Metallibs on macOS 26 Tahoe on unsupported non-T2 Macs](https://github.com/hackdoc/OCLP-R)\n* [stephandeutsch](https://github.com/stephandeutsch/OpenCore-Legacy-Patcher/)\n    * for fixing USB1.1 compatability with Sequoia and Tahoe\n* [coolkid418](https://github.com/coolkid418)\n    * making a dark mode icon for BridgePatcher\n* [vytska69](https://github.com/vytska69)\n    * [developing patches for the T2 chip](https://github.com/vytska69/OpenCore-Legacy-Patcher)\n    * [Developing Secure Enclave Processor (SEP) timeout patches](https://github.com/vytska69/OpenCore-Legacy-Patcher)\n    * [workflow files](https://github.com/vytska69/OpenCore-Legacy-Patcher)\n  \n* [peltorio](https://github.com/peltorio/)\n    * Fix a critical bug in GitHub Actions by changing macos-version to macos-15\n* [kodeaqua](https://github.com/kodeaqua)\n    * for research on MacBook Air 2018-2019 hardware to fix boot issues\n* [GUTY345](https://github.com/GUTY345)\n    * for fixing a bug in BridgePatcher where USB-Map.plist\'s syntax was invalid and SMBIOS spoofing bug that prevented SMBIOS spoofing from working properly on T2 Macs\n    * [fix graphics accelaration on Intel UHD Graphics 630 on unsupported T2 Macs](https://github.com/GUTY345/OpenCore-Legacy-patcher-t2chip-fixBugs/tree/main)\n    * [fix your Mac is not supported by macOS 26 Tahoe](https://github.com/GUTY345/OpenCore-Legacy-patcher-t2chip-fixBugs/tree/main)\n    * [fix Unsupported Mantissa speed kernel panics on T2 MacBooks](https://github.com/GUTY345/OpenCore-Legacy-patcher-t2chip-fixBugs/tree/main)\n* [EduCovas](https://github.com/covasedu)\n  * macOS Tahoe patch set\n  * [non-Metal patch set](https://github.com/moraea/non-metal-frameworks) for nVidia Tesla/Fermi/Maxwell/Pascal, AMD TeraScale 1/2, and Intel Core 1st/2nd Generation GPUs\n  * [3802 Metal patch set](https://github.com/moraea/misc-patches/tree/main/3802-Metal-15) and [MetallibSupportPkg](https://github.com/dortania/MetallibSupportPkg) for nVidia Kepler and Intel Core 3rd/4th Generation GPUs\n  * Metal bundle patches and shims for [nVidia Kepler](https://github.com/moraea/misc-patches/tree/main/Kepler%2013%2B), [AMD GCN 1 - 4](https://github.com/moraea/misc-patches/tree/main/GCN%2013%2B), and [AMD GCN 5 (Vega)](https://github.com/moraea/misc-patches/tree/main/vega%2013%2B)\n  * [IOSurface offset patches](https://github.com/moraea/misc-patches/tree/main/Sonoma%2014.4%20IOSurface) for nVidia Kepler, AMD GCN 1 - 5, and Intel Core 3rd - 6th Generation GPUs\n  * [legacy Wi-Fi patch set](https://github.com/moraea/unsupported-wifi-patches) restores functionality for Wi-Fi cards in all 2007 - 2017 models\n  * [T1 patch set](https://github.com/moraea/misc-patches/tree/main/T1-Patch) restores Touch ID, Apple Pay, and other secure functionality in 2016 - 2017 models\n  * AppleGVA downgrade for accelerated video decoding on 2012 - 2016 models\n  * OpenCL and OpenGL downgrade for AMD GCN\n  * [USB 1 patch](https://github.com/moraea/misc-patches/tree/main/IOUSBHostFamily-14.4)\n* [ASentientHedgehog](https://github.com/moosethegoose2213)\n  * [non-Metal patch set](https://github.com/moraea/non-metal-frameworks) for nVidia Tesla/Fermi/Maxwell/Pascal, AMD TeraScale 1/2, and Intel Core 1st/2nd Generation GPUs\n* [ASentientBot](https://github.com/ASentientBot)\n  * macOS Tahoe patch set\n  * 3802 MTLCompiler, 31001 MTLCompiler, T1, WiFi patch sets\n  * [dsce](https://github.com/moraea/dsce) and [shared code](https://github.com/moraea/moraea-common) used by some other patches\n* [cdf](https://github.com/cdf)\n  * Mac Pro on OpenCore Patch set and documentation\n  * [Innie](https://github.com/cdf/Innie) and [NightShiftEnabler](https://github.com/cdf/NightShiftEnabler)\n* [Syncretic](https://forums.macrumors.com/members/syncretic.1173816/)\n  * [AAAMouSSE](https://forums.macrumors.com/threads/mp3-1-others-sse-4-2-emulation-to-enable-amd-metal-driver.2206682/), [telemetrap](https://forums.macrumors.com/threads/mp3-1-others-sse-4-2-emulation-to-enable-amd-metal-driver.2206682/post-28447707) and [SurPlus](https://github.com/reenigneorcim/SurPlus)\n* [dosdude1](https://github.com/dosdude1)\n  * Main author of the [original GUI](https://github.com/dortania/OCLP-GUI)\n  * Development of previous patchers, laying out much of what needs to be patched\n* [parrotgeek1](https://github.com/parrotgeek1)\n  * [VMM Patch Set](https://github.com/dortania/OpenCore-Legacy-Patcher/blob/4a8f61a01da72b38a4b2250386cc4b497a31a839/payloads/Config/config.plist#L1222-L1281)\n* [BarryKN](https://github.com/BarryKN)\n  * Development of previous patchers, laying out much of what needs to be patched\n* [mario_bros_tech](https://github.com/mariobrostech) and the rest of the Unsupported Mac Discord\n  * Catalyst that started OpenCore Legacy Patcher\n* [arter97](https://github.com/arter97/)\n  * [SimpleMSR](https://github.com/arter97/SimpleMSR/) to disable firmware throttling in Nehalem+ MacBooks without batteries\n* [Mr.Macintosh](https://mrmacintosh.com)\n  * Endless hours helping architect and troubleshoot many portions of the project\n* [flagers](https://github.com/flagersgit)\n  * Aid with Nvidia Web Driver research and development\n  * [non-Metal patch set](https://github.com/moraea/non-metal-frameworks) for nVidia Tesla/Fermi/Maxwell/Pascal, AMD TeraScale 1/2, and Intel Core 1st/2nd Generation GPUs\n  * [Metal bundle interposer](https://github.com/moraea/misc-patches/tree/main/sequoia%2031001%20interposer) for AMD GCN 1 - 5 and Intel Core 5th/6th Generation GPUs\n  * LegacyRVPL, SnapshotIsKill, etc. to aid in rapid testing and development\n* [joevt](https://github.com/joevt)\n  * [FixPCIeLinkrate](https://github.com/joevt/joevtApps)\n* [Jazzzny](https://github.com/Jazzzny)\n  * Research and various contributions to the project\n  * UEFI Legacy XHCI research and development\n  * NVIDIA OpenCL research and development\n  * `MacBook5,2` research and development\n    * LegacyKeyboardInjector\n  * Pre-Ivy Bridge Aquantia Ethernet Patch\n  * Non-Metal Photo Booth Patch for Monterey+\n  * GUI and Backend Development\n    * Updater UI\n    * macOS Downloader UI\n    * Downloader UI\n    * USB Top Case probing\n    * Developer root patching\n  * Vaulting implementation\n  * macOS 15 3802 Helios Research\n  * UEFI bootx64.efi research\n  * universal2 build research\n  * Various documentation contributions\n* [crystall1nedev](https://github.com/crystall1nedev)\n  * Various patcher and PatcherSupportPkg contributions\n* Amazing users who\'ve graciously donate hardware:\n  * [JohnD](https://forums.macrumors.com/members/johnd.53633/) - 2013 Mac Pro\n  * [SpiGAndromeda](https://github.com/SpiGAndromeda) - AMD Vega 64\n  * [turbomacs](https://github.com/turbomacs) - 2014 5k iMac\n  * [vinaypundith](https://forums.macrumors.com/members/vinaypundith.1212357/) - MacBook7,1\n   * [ThatStella7922](https://github.com/ThatStella7922) - 2017 13" MacBook Pro (A1708)\n  * zephar - 2008 Mac Pro\n  * jazo97 - 2011 15" MacBook Pro\n  * And others (reach out if we forgot you!)\n* MacRumors and Unsupported Mac Communities\n  * Endless testing and reporting issues\n* Apple\n  * for macOS and many of the kexts, frameworks and other binaries we reimplemented into newer OSes\n'

        # Call your custom function here.
        html_body = self.render_markdown(markdown_text)

        html_document = f"""<!doctype html>
<html>
<head>
    <meta charset="utf-8">

    <style>
        :root {{
            color-scheme: light;

            --background: #ffffff;
            --foreground: #202124;
            --muted-foreground: #5f6368;
            --link: #268bd2;
            --code-background: #f0f0f0;
            --border: #999999;
            --blockquote-border: #cccccc;
        }}

        html,
        body {{
            background: var(--background);
            color: var(--foreground);
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                         sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 24px;
            line-height: 1.5;
        }}

        img {{
            max-width: 100%;
            height: auto;
        }}

        input[type="checkbox"] {{
            width: 1.1em;
            height: 1.1em;
            vertical-align: middle;
            margin-right: 0.4em;
        }}

        .task-list-item {{
            list-style: none;
        }}

        ul:has(.task-list-item) {{
            padding-left: 0;
        }}

        pre {{
            overflow-x: auto;
            padding: 12px;
            border-radius: 6px;
            background: var(--code-background);
            color: var(--foreground);
        }}

        code {{
            background: var(--code-background);
            color: var(--foreground);
        }}

        table {{
            border-collapse: collapse;
        }}

        th,
        td {{
            border: 1px solid var(--border);
            padding: 6px 10px;
        }}

        blockquote {{
            margin-left: 0;
            padding-left: 16px;
            border-left: 4px solid var(--blockquote-border);
            color: var(--muted-foreground);
        }}

        a {{
            color: var(--link);
        }}

        @media (prefers-color-scheme: dark) {{
            :root {{
                color-scheme: dark;

                --background: #0d1117;
                --foreground: #e6edf3;
                --muted-foreground: #8b949e;
                --link: #58a6ff;
                --code-background: #161b22;
                --border: #30363d;
                --blockquote-border: #30363d;
            }}
        }}
    </style>
</head>
<body>
{html_body}
</body>
</html>
"""

        # This lets relative images and links resolve relative to the
        # directory containing the Markdown file.
        base_url = Path(self.constants.app_icon_path_png).resolve().parent.as_uri() + "/"

        self.webview.SetPage(html_document, base_url)


    def render_markdown(self, text: str):
        # Convert bare GitHub-style task lines into Markdown list items.
        #
        # Input:
        #   [X] Installer boots
        #
        # Becomes:
        #   - [X] Installer boots
        text = re.sub(
            r"^(\s*)(\[[ xX]\])\s+(.*)$",
            r"\1- \2 \3",
            text,
            flags=re.MULTILINE,
        )

        html = markdown.markdown(
            text,
            extensions=[
                "extra",
                "tables",
                "fenced_code",
                "sane_lists",
            ],
        )

        # Convert [X] and [ ] inside <li> elements into HTML checkboxes.
        def checkbox_replacement(match):
            checked = match.group(1).lower() == "x"

            return (
                '<li class="task-list-item">'
                '<input type="checkbox" '
                f'{"checked " if checked else ""}'
                'disabled> '
            )

        html = re.sub(
            r"<li>\[([ xX])\]\s*",
            checkbox_replacement,
            html,
            flags=re.IGNORECASE,
        )

        return html
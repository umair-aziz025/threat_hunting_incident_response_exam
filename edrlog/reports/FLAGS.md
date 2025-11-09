# All Captured Flags - EDR Telemetry Validation

## Challenge Completion: ✅ 20/20 Flags

---

## 🔴 TRUE POSITIVES (BLOCK) - Malicious Detections

1. **Unsigned loader installs vulnerable signed driver (BYOVD)**
   ```
   RTL{ad0a1d2a9086d5fe4aca1a383010c709}
   ```

2. **DLL injection into notepad.exe using CreateRemoteThread**
   ```
   RTL{c3ac7be0cdec2c7249a77a19990d9d23}
   ```

3. **Dropper downloads and stages second-stage payload**
   ```
   RTL{c22a34f733e0a12adc9bb475700f8b5a}
   ```

4. **LSASS memory dump via alternate method (mimikatz variant)**
   ```
   RTL{4af235d9793ce10838d54c85f9b73a2d}
   ```

5. **Hookchain.exe injects code into explorer.exe**
   ```
   RTL{cedab8593cbebb64b1df88a50fc0655f}
   ```

6. **LOLBIN: certutil downloads remote payload**
   ```
   RTL{fb3cbf4414f0c9cc5ca3517320e46c98}
   ```

7. **LOLBIN: regsvr32 executes remote scrobj COM script**
   ```
   RTL{858b6e3aee6cfc9ced74ebbd8d25ae8b}
   ```

8. **LOLBIN: mshta loads remote HTA executing commands**
   ```
   RTL{cf9a9c228146a472a9fa2c865d4b6b4e}
   ```

9. **LOLBIN: bitsadmin transfers staged binary**
   ```
   RTL{d57aa06f52fbe6b79cb8454d408afede}
   ```

10. **LOLBIN: installutil runs malicious assembly**
    ```
    RTL{7a584a85cb14e7c0af96160cb2ac5428}
    ```

---

## 🟢 FALSE POSITIVES (ALLOW) - Benign Detections

11. **Backup agent bulk file reads & HTTPS upload to cloud**
    ```
    RTL{a13077f6a5847956825368f852920579}
    ```

12. **Driver update utility installing vendor-signed driver**
    ```
    RTL{5a1e4b50e9e8ce0185ec62831e91d9ca}
    ```

13. **ProcDump used to capture w3wp.exe for troubleshooting**
    ```
    RTL{fe34a82e7db8ac9d066987b53decb854}
    ```

14. **MSBuild post-build PowerShell script (Dev pipeline)**
    ```
    RTL{12465b857918ad06cd7984e1f26ce220}
    ```

15. **Remote admin tool pushes patch via PsExec-like service**
    ```
    RTL{83fc44238665230d9ba4c23b96a2ab5f}
    ```

16. **LOLBIN: certutil verifies certificate chain for VPN**
    ```
    RTL{fc580f0a59e920ed070560d202102f0d}
    ```

17. **LOLBIN: regsvr32 registers vendor DLL (signed)**
    ```
    RTL{9d20dcabd0dd0f9d2dd3adaef461a898}
    ```

18. **LOLBIN: mshta launches corporate enrollment**
    ```
    RTL{c1b9028dfe81f058e581b0187c3b6557}
    ```

19. **LOLBIN: rundll32 opens Control Panel applet**
    ```
    RTL{6ab93c0b42758a165c82462e8abdba2a}
    ```

20. **LOLBIN: bitsadmin used by Windows Update**
    ```
    RTL{0f82f529d5cbb9cf662747bad2aa3137}
    ```

---

## All Flags (One-Liner)
```
RTL{ad0a1d2a9086d5fe4aca1a383010c709} RTL{c3ac7be0cdec2c7249a77a19990d9d23} RTL{c22a34f733e0a12adc9bb475700f8b5a} RTL{4af235d9793ce10838d54c85f9b73a2d} RTL{cedab8593cbebb64b1df88a50fc0655f} RTL{fb3cbf4414f0c9cc5ca3517320e46c98} RTL{858b6e3aee6cfc9ced74ebbd8d25ae8b} RTL{cf9a9c228146a472a9fa2c865d4b6b4e} RTL{d57aa06f52fbe6b79cb8454d408afede} RTL{7a584a85cb14e7c0af96160cb2ac5428} RTL{a13077f6a5847956825368f852920579} RTL{5a1e4b50e9e8ce0185ec62831e91d9ca} RTL{fe34a82e7db8ac9d066987b53decb854} RTL{12465b857918ad06cd7984e1f26ce220} RTL{83fc44238665230d9ba4c23b96a2ab5f} RTL{fc580f0a59e920ed070560d202102f0d} RTL{9d20dcabd0dd0f9d2dd3adaef461a898} RTL{c1b9028dfe81f058e581b0187c3b6557} RTL{6ab93c0b42758a165c82462e8abdba2a} RTL{0f82f529d5cbb9cf662747bad2aa3137}
```

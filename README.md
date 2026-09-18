# ARES-X — .NET Decryption & Reverse Engineering Tool

An alternative to dnSpy/dnSpyEx with local AI integration (Ollama), comprehensive search, real YARA scanning, and protection/packer detection.

---

## ⚠️ Read This First — What Actually Works and What Doesn't

An honest 100% accurate feature status:

| Feature | Status | Details |
|---|---|---|
| Load assembly and display the tree | ✅ **Real** | Powered by dnlib |
| **Decrypt IL → Actual C#** | ✅ **Real** | Uses the same ILSpy engine (`ICSharpCode.Decompiler.CSharpDecompiler`) — produces real, readable C# code, not placeholder text |
| **Real YARA scanning** | ✅ **Real** (requires one-time setup) | Executes the official `yara64.exe` from VirusTotal/yara as a process — run `setup_yara.bat` once |
| Packer detection (ConfuserEx, etc.) | ✅ Real (basic) | Structural checks; can be expanded later |
| Lucene search | ✅ Real | Full indexing and search |
| Ollama integration | ✅ Real | Streaming + retry + circuit breaker |
| **IL modification (Patching)** | ⚠️ Structure is ready, detailed implementation is incomplete | Writing through dnlib works; modifying individual instructions requires additional code |
| Connecting all UI buttons | ⚠️ Partial | Core functions (open file, search) work; some secondary buttons still need wiring |

### **Summary**

You now have a tool that can open .NET files, **actually decompile them into real C# code**, **scan them with real YARA**, search through them, and explain them using local AI.

This is a major difference from the previous version, which contained placeholders.

---

## 🛠️ Requirements (Install Once)

1. **.NET 9 SDK** — https://dotnet.microsoft.com/download/dotnet/9.0
2. Internet connection (only required initially to download NuGet packages and `yara64.exe`)

---

## 🚀 How to Run (3 Steps, All Commands Ready)

### Quick Method (Just Double-Click)

Open the project folder and double-click:

```text
build_and_run.bat
```

This file automatically:

1. Checks whether the .NET SDK is installed
2. Downloads `yara64.exe` (first time only)
3. Runs `dotnet restore` to download the required packages
4. Runs `dotnet build -c Release`
5. Starts the application

### Manual Method (If You Want Control Over Each Step)

Open CMD inside the project folder and run the following commands in order:

```cmd
REM 1. Download the YARA engine (one-time setup)
setup_yara.bat

REM 2. Restore NuGet packages
dotnet restore

REM 3. Build
dotnet build -c Release

REM 4. Run
dotnet run --project src\AresX.UI -c Release
```

After the first successful build, the ready-to-run executable will be located at:

```text
src\AresX.UI\bin\Release\net9.0\AresX.UI.exe
```

You can launch it directly afterward without repeating any of the setup steps.

---

## 🔍 YARA Setup in Detail

`setup_yara.bat` automatically downloads the official YARA release from VirusTotal/yara on GitHub and places it at:

```text
tools\yara\yara64.exe
```

If the automatic download fails (for example, because of a corporate firewall), download it manually from:

https://github.com/VirusTotal/yara/releases

Then place `yara64.exe` at the following path:

```text
tools\yara\yara64.exe
```

The default YARA rules are located at:

```text
rules\yara\protector_detection.yar
```

You can add your own custom rules to the same directory. ARES-X automatically loads the rules when opening a file.

---

## 📁 Project Structure

```text
ARES-X/
├── build_and_run.bat          ← Double-click this (automates everything)
├── setup_yara.bat             ← Download/setup YARA separately if needed
├── AresX.sln                  ← Or open manually with Visual Studio
├── README.md                  ← This file
├── rules/yara/                 ← Default YARA rules
├── tools/yara/                 ← yara64.exe is downloaded here
├── docs/                       ← Complete architectural documentation (Word)
└── src/
    ├── AresX.Core/             ← Models and interfaces
    ├── AresX.Decompiler/      ← Real decompilation (ICSharpCode.Decompiler)
    ├── AresX.AI/               ← Ollama integration
    ├── AresX.Analysis/         ← Real YARA scanning + Packer detection
    ├── AresX.Search/           ← Lucene.NET search
    ├── AresX.Patching/         ← File modification/writing (dnlib)
    ├── AresX.UI/               ← UI (Avalonia)
    └── AresX.Tests/            ← Unit tests
```

---

## 🤖 Enabling Local AI (Optional)

1. Download Ollama from https://ollama.com
2. Run:

```cmd
ollama pull deepseek-coder:6.7b-instruct-q4_K_M
ollama serve
```

3. Open ARES-X — the status indicator at the top should automatically turn green.

Everything runs locally. No data is sent outside your machine.

---

## ❓ If You Encounter a Build Error

Copy the complete error message and send it over. Most issues are caused by:

- An outdated .NET version — make sure you have exactly version 9.x by running:
  ```cmd
  dotnet --version
  ```
- A firewall blocking NuGet or `yara64.exe` downloads
- The project path containing Arabic characters or special symbols — move the folder to a simple English-only path such as:
  ```text
  C:\ARES-X
  ```

---

## ⚖️ Usage Notice

ARES-X is a static analysis tool intended for security researchers, malware analysts, and digital forensics teams. Use it only on files you are legally authorized to analyze.

---
## 📞 Contact

- Discord: <a href="https://discordapp.com/users/970282290905231390">@lumelisse</a>
- Discord: <a href="https://discordapp.com/users/219449504229752832">@Pokerface</a>
- Discord: <a href="https://discord.gg/MsxgXWA9Mt">@Server</a>

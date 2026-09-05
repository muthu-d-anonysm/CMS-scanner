# CMS Scanner & Detection Tool

A concurrent **CMS detection and security scanning tool written in Go**.

The tool performs lightweight HTTP-based technology fingerprinting against target URLs and, when a supported CMS is detected, automatically invokes the corresponding external security scanner. Scan results are organized into per-target files and a consolidated summary.

> ⚠️ **For authorized security testing only.**
> Only scan websites, applications, and infrastructure that you own or have explicit permission to test.

---

## ✨ Features

* 🔎 HTTP-based CMS and technology fingerprinting
* ⚡ Concurrent scanning of multiple targets
* 🧵 Configurable scanner concurrency per target
* 🛡️ Optional SSL certificate verification bypass
* 🔧 Automatic integration with external security scanners
* 📄 Individual scan result files
* 📋 Consolidated `summary.txt` report
* 🌐 Optional HTML reports
* 📁 Organized output using configurable groups
* ⏱️ Scanner execution timeout protection
* 🖥️ Verbose scanner output mode
* 🔗 Custom User-Agent for HTTP probes

---

## 🧩 Supported Technologies

The current detection engine supports fingerprinting for:

| Technology               | Detection |
| ------------------------ | --------- |
| WordPress                | ✅         |
| Joomla                   | ✅         |
| Drupal                   | ✅         |
| SilverStripe             | ✅         |
| TYPO3                    | ✅         |
| Adobe Experience Manager | ✅         |
| vBulletin                | ✅         |
| Moodle                   | ✅         |
| osCommerce               | ✅         |
| ColdFusion               | ✅         |
| JBoss                    | ✅         |
| Oracle E-Business Suite  | ✅         |
| phpBB                    | ✅         |
| PHP-Nuke                 | ✅         |
| DotNetNuke               | ✅         |
| Umbraco                  | ✅         |
| PrestaShop               | ✅         |
| OpenCart                 | ✅         |
| Magento                  | ✅         |

## The technologies are detected using HTTP response headers, response-body fingerprints, and additional HTTP `HEAD` probes against common paths.

## 🔧 Scanner Integrations

When a supported CMS is detected, the tool can invoke the corresponding external scanner.

| CMS          | Scanner         |
| ------------ | --------------- |
| Joomla       | `joomscan`      |
| WordPress    | `wpscan`        |
| Drupal       | `droopescan`    |
| SilverStripe | `droopescan`    |
| Magento      | `magescan.phar` |

The scanner executable must be available in the system `PATH`, except for the Magento PHAR which is expected in the current directory.

---

## 📋 Requirements

### Go

A recent Go installation is recommended.

### External Scanners

Install the scanners you intend to use and make sure they are accessible from your `PATH`.

For example:

```bash
joomscan
wpscan
droopescan
```

For Magento scanning:

```text
magescan.phar
```

Place `magescan.phar` in the tool's working directory.

> The tool checks whether scanner executables exist before attempting to run them. Missing scanners are skipped rather than causing the entire scan to fail.

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

Build the binary:

```bash
go build -o cms-scanner .
```

Run:

```bash
./cms-scanner -u https://example.com
```

---

## 💻 Usage

### Scan a single URL

```bash
./cms-scanner -u https://example.com
```

### Scan multiple URLs

Create an input file:

```text
https://example.com
https://example.org
https://example.net
```

Then:

```bash
./cms-scanner -i urls.txt
```

---

## ⚙️ Command-Line Options

| Option              |   Default | Description                                          |
| ------------------- | --------: | ---------------------------------------------------- |
| `-u`                |         — | Single URL to scan                                   |
| `-i`                |         — | File containing URLs, one per line                   |
| `-v`                |   `false` | Display scanner output while running                 |
| `-o`                |    `text` | Output format: `text` or `html`                      |
| `-no-verify-ssl`    |   `false` | Disable SSL certificate verification for HTTP probes |
| `-concurrency`      |       `2` | Number of target scans running concurrently          |
| `-scan-concurrency` |       `2` | Number of scanner processes per target               |
| `-group`            | `default` | Output group/subfolder name                          |

These options correspond to the command-line flags implemented by the tool.

---

## 📌 Examples

### Basic scan

```bash
./cms-scanner -u https://example.com
```

### Scan a list of targets

```bash
./cms-scanner -i targets.txt
```

### Increase target concurrency

```bash
./cms-scanner \
  -i targets.txt \
  -concurrency 5
```

### Increase scanner concurrency

```bash
./cms-scanner \
  -i targets.txt \
  -scan-concurrency 4
```

### Verbose mode

```bash
./cms-scanner \
  -u https://example.com \
  -v
```

### HTML reports

```bash
./cms-scanner \
  -u https://example.com \
  -o html
```

### Disable SSL verification for HTTP probes

```bash
./cms-scanner \
  -u https://example.com \
  -no-verify-ssl
```

### Organize results into a group

```bash
./cms-scanner \
  -i targets.txt \
  -group microsoft
```

---

## 📂 Output Structure

Results are stored under the `outputs/` directory.

Example:

```text
outputs/
└── microsoft/
    ├── scan_output_example_com_wordpress.txt
    ├── scan_output_example_com_joomla.txt
    ├── scan_output_example_com_wordpress.html
    └── summary.txt
```

The group directory is automatically created when the scan starts.

---

## 📄 Summary Report

After scanning all targets, the tool creates:

```text
outputs/<group>/summary.txt
```

The summary contains the targets in their original input order together with the captured scanner output.

Example:

```text
1. https://example.com

=== Target: https://example.com ===
Technologies detected: wordpress

--- Running wordpress scanner on https://example.com ---
----- WORDPRESS output for https://example.com -----

[scanner output]

------------------------------------------------------------
```

---

## 🌐 HTML Reports

HTML output can be enabled with:

```bash
-o html
```

The generated report contains:

* Target URL
* Detected CMS
* Scan timestamp
* Scanner results

Scanner output is HTML-escaped before being inserted into the report.

---

## 🔍 How It Works

The scanner follows a simple workflow:

```text
                 ┌──────────────────┐
                 │    Target URLs   │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │   HTTP GET Probe │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ Fingerprint HTTP │
                 │ Headers + Body   │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ Additional HEAD  │
                 │      Probes      │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ CMS Detected?    │
                 └───────┬───┬──────┘
                         │   │
                       No│   │Yes
                         │   │
                         ▼   ▼
                    ┌─────┐ ┌────────────────┐
                    │Skip │ │ Run CMS Scanner│
                    └─────┘ └───────┬────────┘
                                    │
                                    ▼
                           ┌──────────────────┐
                           │ Save Scan Results│
                           └────────┬─────────┘
                                    │
                                    ▼
                           ┌──────────────────┐
                           │  Summary / HTML  │
                           └──────────────────┘
```

The implementation first performs an HTTP GET, examines headers and a limited portion of the response body for technology fingerprints, and then performs additional `HEAD` probes for certain common CMS paths.

---

## ⚡ Concurrency

The tool supports two levels of concurrency.

### Target concurrency

Controls how many target URLs are processed simultaneously:

```bash
-concurrency 5
```

### Scanner concurrency

Controls how many scanner processes can run simultaneously for each individual target:

```bash
-scan-concurrency 3
```

## This allows large target lists to be processed efficiently while limiting the number of external scanner processes.

## ⏱️ Timeouts

HTTP probes use an **8-second HTTP timeout**.

External scanner processes have a maximum execution time of **20 minutes**.

## If a scanner exceeds the configured execution limit, the process is terminated and the timeout is recorded in the output.

## 🛡️ Security & Responsible Use

This project is intended for:

* Authorized penetration testing
* Bug bounty programs
* Security research
* Internal security assessments
* CMS inventory and reconnaissance
* Laboratory environments

**Do not use this tool against systems without authorization.**

The user of this software is responsible for ensuring that all scanning activity complies with applicable laws, contracts, bug bounty rules, and organizational policies.

The developers and contributors are not responsible for misuse or damage resulting from unauthorized scanning.

---

## ⚠️ Limitations

CMS detection is fingerprint-based and therefore is not guaranteed to identify every deployment.

A CMS may not be detected when:

* Fingerprint indicators are removed
* Responses are heavily customized
* Security controls block probes
* The application requires authentication
* The target uses unusual routing
* HTTP requests are filtered

Additionally, detection does not necessarily mean that the corresponding scanner is installed. The tool skips scanner execution when the required executable cannot be found.

---

## 🏗️ Project Structure

A typical repository can be organized as:

```text
.
├── main.go
├── magescan.phar
├── README.md
├── LICENSE
├── go.mod
└── outputs/
```

---

## 🤝 Contributing

Contributions are welcome.

Potential improvements include:

* Additional CMS fingerprints
* Additional scanner integrations
* Improved fingerprint confidence scoring
* JSON output support
* Better error handling
* Custom fingerprint configuration
* Additional report formats
* Scanner configuration profiles

Before submitting a pull request:

1. Test your changes locally.
2. Keep changes focused.
3. Document new command-line options.
4. Ensure existing functionality continues to work.

---

## 📜 License

This project is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for the full license text.

---

## 👤 Author

**[Your Name]**

Security Researcher / Offensive Security

---

## ⭐ Disclaimer

This project is provided for educational and authorized security-testing purposes only.

By using this software, you agree that you are responsible for obtaining appropriate authorization before scanning any target.

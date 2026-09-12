# Vianto

<img width="1233" height="141" alt="изображение" src="https://github.com/user-attachments/assets/35e61e4b-373e-4dd5-aa60-e905510561e0" />

VIANTO (Virus Analyzer Tool) is an open-source tool written entirely in Python. It performs a four-stage file check: starting with a basic analysis of file size and checksums, followed by scanning via the VirusTotal API (which requires a user-provided token), then a core content inspection and line-by-line information search, and finally, verification of any discovered IPv4 and IPv6 addresses, domains, and URLs. The tool is designed as a utility for analyzing files for malicious content.

# Installation

```
git clone https://github.com/Vesel4ak31/Vianto.git
cd Vianto
pip install -r requirements.txt --break-system-packages
```
To view all  of tool's parameters, run:
```
python3 vianto.py -h
```


| Flag | Full name / Type | Description |
| :--- | :--- | :--- |
| **-f** | `--file-path` | File path to check |
| **-vt** | `--virus-total` | VirusTotal API key for malware check |
| **-l** | `--log` | This parameter is responsible for logging all program actions |
| **-t** | `--timeout` | Custom timeout |
| **-sfoc** | `--skip-file-options-check` | Skip file options check |
| **-smc** | `--skip-malware-check` | Skip malware check |
| **-sfc** | `--skip-file-check` | Skip file check |
| **-sfic** | `--skip-file-info-check` | Skip file info check |
| **-rt** | `--random-timeout` | Random timeout range, for example 'random timeout \'2 5\'' |
| **-j** | `--jitter` | Flag for adding a timeout to the current one. A negative timeout can be specified. Useful in combination with the --random-timeout flag. |

<img width="1691" height="323" alt="изображение" src="https://github.com/user-attachments/assets/5e5b2e78-1e22-46da-be4e-f23e46d0fbc6" />

# Use case and information about analysis
A typical use case for the tool is presented below:
```
python3 vianto.py ./launch.bat --virus-total "bcc0ebabea49adda48v5a38dffb337799c35c75f5c94f265b1a9a313a45634564" --random-timeout "3-10" -o output.txt --jitter -1.2
```
<img width="1648" height="320" alt="изображение" src="https://github.com/user-attachments/assets/5140f3bc-d576-4d9c-a251-5a41108f1e04" />

The screenshot above shows the initial stage of the file scan: checking its size, checksums, and certain metadata. You can skip any specific check stage by specifying the corresponding flag. If you are analyzing a small file, keep in mind that the content analysis stage—checking for malicious code—can take a long time if there are many matches. The example shows the analysis of a .bat file used to launch the Ghidra tool. Naturally, it contains nothing malicious, but this is merely an example; the results could differ during an actual analysis.

<img width="1349" height="243" alt="изображение" src="https://github.com/user-attachments/assets/9acb1936-b32f-42dd-a3d1-e0e385bcd341" />

The second stage of the check involves scanning the file for malicious content. For instance, if you are dealing with an .exe file that yields no results during content analysis, you can check it for malicious content using the VirusTotal API. You must manually provide a VirusTotal API token for the check using the `-vt` flag. Your token is not transmitted anywhere, and obtaining the token itself is completely free; you simply need to log in to your account and copy it. The malicious content check outputs 10 parameters. As shown in the screenshot, the majority of antivirus programs deemed the Ghidra executable file safe. You can also skip this stage by specifying the appropriate flag.

<img width="940" height="273" alt="изображение" src="https://github.com/user-attachments/assets/5ef62af8-b7d1-4a87-baa2-0bf7b2dd9bcb" />

The third stage of the check involves analyzing the file's actual content. As shown in the screenshot above, the tool scans the file line by line, looking for matches defined in the configuration file. It searches for IPv4 and IPv6 addresses, domains, URLs, phone numbers, email addresses, MAC addresses, potential executable filenames, MD5/SHA256/SHA512 hashes, and strings encoded in Base64 or Base32 (note that checking for obfuscated Base64 or Base32 strings can often trigger false positives; these strings typically appear as random sequences of characters and letters, and you can use free online decoders to convert them into a readable format). It also looks for private key headers, SSH authorization keys, AWS Access and Secret Keys, Telegram bot tokens, as well as tokens for GitHub, Elastic, Slack, Google API, and JWS.

Additionally, the tool can identify potential passwords or database connection strings. All regex-based search configurations are located in the `config.py` file. If you wish to remove or add a parameter, make your changes only in that file. It is strongly advised not to remove the search patterns for IPv4/IPv6 addresses, domains, and URLs. These parameters are critical for the fourth stage of the check, and removing them could cause errors. Please make changes carefully to avoid breaking anything.

<img width="1471" height="502" alt="изображение" src="https://github.com/user-attachments/assets/1b484a6c-e70b-409f-b94e-5512df1ebaa2" />

The final verification stage involves checking IPv4 and IPv6 addresses, domains, and URLs for malicious content using the VirusTotal API. As with file scanning, you must manually provide the token. The check also outputs several parameters—as shown in the screenshot above—indicating whether the item being checked is safe. You can also skip this verification stage, just like the previous ones, by specifying the appropriate flag. Your VirusTotal token is not transmitted anywhere. When testing URLs, this process may take some time due to the nature of the scanning procedure.

<img width="2183" height="1320" alt="изображение" src="https://github.com/user-attachments/assets/6ed002df-e74a-4b99-b168-e990b9660e74" />

# About logging

Using the -o flag you can log all program actions. By “logging everything,” I mean literally everything. Each parameter will be written to the file you specify: from clearing the cache to setting a random timeout. This is necessary for content analysis. The start and end of the scan will be separated by 60 “-” signs and the words “START” or “END” respectively. The logs will indicate the exact date with milliseconds. Also, after the tool completes, the total execution time will be displayed.

# Useful Options

The tool offers a total of three useful options.

The first function allows you to specify a custom timeout using the `--timeout` flag. This is useful when dealing with response blocking from VirusTotal. You can even specify a range of values ​​for a random timeout using the `--random-timeout` flag. For example, if you specify the value "2-5," your operating system will select a random number using a pseudo-random number generator. This selection is virtually 100% random, ensuring the value is unpredictable.

The final notable feature is the `--jitter` flag. This value can be negative and simply adds a specific amount to the current timeout. By default, this parameter is set to 0.0, meaning it has no effect on the primary timeout setting. However, if a value is specified, it is added to the current timeout. This is useful when combined with the random timeout feature to control the degree of randomness.
The command to run with these parameters looks like this:
```
python3 vianto.py file.bat --random-timeout "3-10" --jitter -2.7
```

# Disclaimer

This tool is intended solely for the legal auditing of files for malicious content. The author assumes no liability for the unauthorized scanning of files for the purpose of obtaining computer information.

# License

This tool is distributed under the MIT License. For your convenience, I've included the license here:



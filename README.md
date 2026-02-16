# Cocos Decryptor Ultimate Pro
**Developer: Jason Peixoto**

Cocos Decryptor Ultimate Pro is a high-performance tool designed to automate the extraction, analysis, and decryption of Cocos2d-js Android applications. It features a real-time GUI with colored logging, automated XXTEA key discovery, and source code formatting.

## 1. Prerequisites (Installation Guide)

Ensure the following tools are installed on your macOS system:

### A. Reverse Tool (The Engine)
The core decryption is handled by the reverse tool.
1. Source: https://github.com/zboralski/reverse
2. Build Instructions:
   - git clone https://github.com/zboralski/reverse.git
   - cd reverse
   - go build
3. Note: Take note of the absolute path to the generated reverse binary.

### B. System Dependencies (Homebrew)
Install the required binaries via Homebrew:

- brew install apktool
- brew install prettier

### C. Python Environment
Install the Python library for the interface:

pip3 install PyQt5

## 2. Configuration and First Run

1. Launch the App:
   python3 DecryptCococas.py
2. Open Settings: Click the "Settings" button at the top left.
3. Configure Binaries: Enter the absolute paths to your tools.
   - Apktool: /opt/homebrew/bin/apktool
   - Prettier: /opt/homebrew/bin/prettier
   - Reverse: /Users/YOUR_NAME/path/to/reverse/reverse
4. Save: Click "Save Settings". These are stored in config.json.

## 3. Usage Workflow

1. Select Project Files:
   - Zip Container: Browse for the .zip file containing your encrypted APKs.
   - Output Folder: Choose where you want the decrypted source to live.
2. Start Decryption: Click the red "Decrypt Cocoa's" button.
   - The app clears the previous console logs and the Decryption Key field.
   - Step 0-1: Unzips the container and extracts all discovered APKs.
   - Steps 2-4: Scans all folders for script signatures and hex headers.
   - Step 5: Automatically performs a global search for libcocos.so and index.jsc to bruteforce the XXTEA key.
   - Steps 6-7: Decrypts all files globally and runs Prettier to format the code.
3. Access Results: Once the "DECRYPTION PROCESS COMPLETE" message appears:
   - Click any blue file link in the console to "Reveal in Finder".
   - The final decryption key is printed at the very bottom of the log.
   - The Decryption Key field will flash yellow to grab your attention.

## 4. Troubleshooting

### Permission Denied
If the console reports a permission error when executing reverse or apktool, run:
chmod +x /path/to/your/binary

### Prettier/Node Errors
If Step 7 fails with "env: node: No such file or directory", ensure Node.js is installed (brew install node).

### Environment Checker
For a quick health check of your setup, run the included utility:
python3 check_env.py
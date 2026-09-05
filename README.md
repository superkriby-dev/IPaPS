<h1 align="center">
  <img src="https://i.ibb.co/nq3zFy31/banner-ipaps.png" alt="banner" width="400">
</h1>

<p align="center">
  IPAPS - An advanced networking utility for finding information about a domain.

# Details
This project is wonky and tested only on my personal computer.
If you experience any errors or complications while using this tool, feel free to report issues or bugs to the [Issues Tab](https://github.com/superkriby-dev/IPaPS/issues)
I will be checking the issues tab every once in a while. So do not mass make issues, please be patient.

# Requirements
- Relatively decent internet.
- Rust to be installed, if you don't know how to install rust. Refer to the installation segment.
- Windows 11 or Windows 10 (Windows 10 is untested. Use at your own risk.)

# Installation
1. Install Rust; If you don't have rust, or do not know how to install it, go [HERE](https://rust-lang.org/tools/install/) or https://rust-lang.org/tools/install/
2. Download the latest executable file, or compile the executable yourself from the source code!
3. Simply run it, if you want you can run it as Administrator, though it is not required.
4. If you encounter issues, report them to the [Issues Tab](https://github.com/superkriby-dev/IPaPS/issues) as said before.

# Features
1. IPv4 Finder - This feature allows you to find the IPv4 of any domain, for example if you were to scan "google.com" you would get "142.250.188.14" as the response.
2. TCP Port Scanning - This features (after using the IPv4 Finder) allows you to brute force all 65,535 TCP ports available on the IP (You can also configure the timeout response and how many workers are actively scanning)
3. IP Geolocation - This feature (after using the IPv4 Finder) allows you to locate where the IPv4 is located, this will not give you an address only a city.
4. Reverse DNS Lookup - This feature (after using the IPv4 Finder) allows you to find the domain accosiated with the IPv4 using [nslookup](https://www.nslookup.io/)

# Compiling From Source
1. Download the code from [latest](https://github.com/superkriby-dev/IPaPS/releases) and extract it.
2. Download Visual Studio Code or just use your Command Prompt.
3. Run ``cargo clean`` in either the Visual Studio Code Terminal or the normal windows 11 / 10 Terminal.
4. Run ``cargo run --release`` to run the project from the terminal (no executable file will be made) or <br>
``cargo build --release`` to make an executable file.
6. Run ``IPaPS.exe`` then there you go, compiled from source!

# Other
Please note that this was made in my free time, so the UI is not well made. I might improve on it later down the line.
Also "IPAPS" stands for "Internet Protocol And Port Scanner" just a fun fact!

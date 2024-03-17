Telegram Reverse Master Bot
=====
[![GitHub stars](https://img.shields.io/github/stars/Anonym0usWork1221/Telegram-Reverse-Master-Bot.svg?branch=master)](https://github.com/Anonym0usWork1221/Telegram-Reverse-Master-Bot/stargazers)
<img src="https://img.shields.io/github/contributors-anon/Anonym0usWork1221/Telegram-Reverse-Master-Bot"/>
[![GitHub forks](https://img.shields.io/github/forks/Anonym0usWork1221/Telegram-Reverse-Master-Bot.svg?branch=master)](https://github.com/Anonym0usWork1221/Telegram-Reverse-Master-Bot/network/members)
[![GitHub issues](https://img.shields.io/github/issues/Anonym0usWork1221/Telegram-Reverse-Master-Bot.svg?branch=master)](https://github.com/Anonym0usWork1221/Telegram-Reverse-Master-Bot/issues)
[![GitHub watchers](https://img.shields.io/github/watchers/Anonym0usWork1221/Telegram-Reverse-Master-Bot.svg?branch=master)](https://github.com/Anonym0usWork1221/Telegram-Reverse-Master-Bot/watchers)
[![Python](https://img.shields.io/badge/language-Python%203-blue.svg)](https://www.python.org)
[![GPT_LICENSE](https://img.shields.io/badge/license-GPL-red.svg)](https://opensource.org/licenses/)
![code size](https://img.shields.io/github/languages/code-size/Anonym0usWork1221/Telegram-Reverse-Master-Bot?branch=master)

Introduction
-----
Welcome to the Telegram Reverse Master Bot, a comprehensive bot designed to handle various reverse engineering, 
hacking, and general functionalities. This bot is developed and maintained by Abdul Moez. It is intended 
for educational and ethical use only, adhering to the GNU General Public License (GPL).

----
Author Information
----
* **Author**: Abdul Moez
* **Email**: abdulmoez123456789@gmail.com
* **Affiliation**: Undergraduate at Government College University (GCU) Lahore, Pakistan
* **GitHub**: [Abdul Moez GitHub](https://github.com/Anonym0usWork1221/)
* **Note**: This file does not provide extensive documentation for usage or for developers, but you can check the doc strings for more information.

-----
License Information
----
The code in this file is governed by the GNU General Public License (GPL), version 3 or later. 
You can redistribute and/or modify this code under the terms of the GPL. 
For detailed information, refer to the official [GNU website](https://www.gnu.org/licenses/).


----
Features
-----
* **Help/Greet**
    * `HI`: How can I help you today?
* **Help Section**
    * `/help`: Provides help on using commands.
    * `/start`: Provides help on using commands.
* **Key Section** 
    * `/generate_key`: Generate a new key.
    * `/set_key`: Set a generated key.
    * `/time_left`: Check the time left for key expiration.
* **Reverse-Engineering Section**
    * `/dump`: Dump data from libraries.
    * `/pseudocode`: Transform binary to C++ pseudocode.
    * `/decompile_apk`: Convert APK files into Java source code.
    * `/mod_lib`: Create anti-cheat libraries (.so files).
    * `/crc32_changer`: Change CRC of files.
    * `/aes_keys`: Search in stored AES keys.
* **Hacking Section**
    * `/gen_combo`: Generate combos of service.
* **General Section**
    * `/courses`: Fetch courses available on Google Drive.

> Max-Uploads - Max_length_file: Less than 100 MB.

----
Setup Instructions
----

* Linux Setup
    * Give root permission to the `linux_installation.sh` file:
        ```shell
        chmod 777 linux_installation.sh
        ```
    * Install the requirements::
        ```shell
        ./linux_installation.sh
        ```
    * Execute the script:
        ```shell
        python3 main.py
        ```

-----
Manually Setup (For other platforms)
-----

1. Install `python >= 3.9`.
2. Install the requirement file using pip: `pip3 install -r requirements.txt --upgrade`.
3. Download the executable of [radare-2](https://github.com/radareorg/radare2/releases/tag/5.8.8) and add its path to environment variable.
4. Download and install the `meson` and `ninja-build` packages, and install them on your target machine.
5. Install the [r2dec](https://github.com/wargio/r2dec-js) extension for radare 2. If you have already made an executable for `r2dec`, skip step 4; otherwise, create an executable as mentioned in the `r2dec` plugin.
6. Download and install the Java Runtime Environment (JRE) and Java Development Kit (JDK). Note: only install the latest versions of them.
7. Execute the script `python3 main.py`


Configuration Documentation for `global_variables.py`
=====

Overview
-----
This document provides comprehensive documentation for the configuration of the `global_variables.py` file for the 
Telegram Reverse Master Bot project.


-----
GlobalVariables Class
----
The `GlobalVariables` class contains several attributes that define global variables used by the bot.
These attributes include:

1. Bot-related variables:
   * `BOT_API_ID`: Telegram API ID for the bot.
   * `BOT_API_HASH`: Telegram API hash for the bot.
   * `BOT_API_TOKEN`: Bot token obtained from BotFather.
   * `PLATFORM`: Operating system platform—Auto Detection.

2. Author and bot version-related variables:
   * `BOT_AUTHORS`: Authors of the bot.
   * `BOT_AVAILABILITY`: Bot availability status.
   * `BOT_NAME`: Bot username.
   * `BOT_VERSION`: Bot version number.

3. Temporary Directories related variables:
   * Various paths for temporary directories used by the bot.

4. Messages and limit variables:
   * `ALLOWED_UPLOAD_MBS`: Maximum allowed upload size in MBs.
   * `BOT_STATICS_MESSAGE`: Statics message for the bot.

5. Link Shorter options:
   * `LINK_SHORTER_API_KEY`: API key for link shortening.

6. Reverse engineering variable section:
   * Variables related to reverse engineering operations.

7. Dumper and PSEUDOCODE section variables:
   * Variables related to dumping and pseudocode generation.

8. Key section variables:
   * Variables related to key generation and management.

9. Available command variables:
   * Commands available for users.

10. Other variables:
    * Miscellaneous variables used by the bot.


----
EnableDisableFeatures Enum
----
The `EnableDisableFeatures` enum defines features and their availability status within the bot. 
These features include:

1. `Temporary Block Message`: Message displayed when a command is temporarily disabled.
2. `Short Generated Link Flag`: Flag indicating the availability of short-generated links.
3. `Key section availability`: Flags indicating the availability of key-related commands.
4. `Reverse engineering section availability`: Flags indicating the availability of reverse engineering commands.
5. `Hacking section availability`: Flags indicating the availability of hacking-related commands.
6. `General section availability`: Flags indicating the availability of general commands.

-----
PreDefinedPipeCommands Enum
-----
The `PreDefinedPipeCommands` enum defines predefined pipe commands for various operations within the bot. 
These commands include:

1. `Removing files`: Commands to remove specific types of files.
2. `APK decompiling tools permissions`: Commands to set execution permissions for APK decompiling tools.

----
BotPrefixes Enum
----
The `BotPrefixes` enum defines prefixes used by the bot for specific purposes. 
These prefixes include:

1. `Dumper imports prefix`: Prefix for imports dumped by the bot.
2. `Bot modding details prefix`: Prefix for modding details messages.
3. `Modding transition details`: Transition details for modding operations.


# Contributors
<a href="https://github.com/Anonym0usWork1221/Telegram-Reverse-Master-Bot/graphs/contributors"><img src="https://contrib.rocks/image?repo=Anonym0usWork1221/Telegram-Reverse-Master-Bot&max=240&columns=18" /></a>

-----------
Support and Contact Information
----------
> If you require any assistance or have questions, please feel free to reach out to me through the following channels:  
* **Email**: `abdulmoez123456789@gmail.com`

> I have also established a dedicated Discord group for more interactive communication:  
* **Discord Server**: `https://discord.gg/RMNcqzmt9f`


-----------

Buy Me a coffee
--------------
__If you'd like to show your support and appreciation for my work, you can buy me a coffee using the 
following payment option:__

**Payoneer**: `abdulmoez123456789@gmail.com`

> Your support is greatly appreciated and helps me continue providing valuable assistance and resources. 
I appreciate your consideration.




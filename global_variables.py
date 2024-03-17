"""
/*
 *  Date     : 2024/03/16
 *  Version  : 0.1
 *  Author   : Abdul Moez
 *  Email    : abdulmoez123456789@gmail.com
 *  Affiliation : Undergraduate at Government College University (GCU) Lahore, Pakistan
 *  GitHub   : https://github.com/Anonym0usWork1221/Telegram-Reverse-Master-Bot
 *
 *  Description:
 *  This code is governed by the GNU General Public License, version 3 or later.
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

GPL License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Ethical Use Warning:
This script is intended to be used for educational and ethical purposes only.
The developer does not endorse or encourage any form of copyright infringement
or illegal sharing of intellectual property. Use this script responsibly and
respect the rights of content creators.
"""

from pathlib import Path
from enum import Enum
from os import path
import platform
import string
import psutil


class GlobalVariables(Enum):
    """
    Global variables used by the bot.

    Attributes:
        BOT_API_ID (str): Telegram API ID for the bot.
        BOT_API_HASH (str): Telegram API hash for the bot.
        BOT_API_TOKEN (str): Bot token obtained from BotFather.
        PLATFORM (str): Operating system platform.

        ... (Other attributes)

        HELP_KEYBOARD_MENU (list): Menu for help section.

    Note:
        Make sure to set the values of the attributes appropriately.

    Warning:
        This code is licensed under the GPL license.
        Use it responsibly and follow ethical guidelines.
    """

    # Bot related variables
    BOT_API_ID: str = "----"  # From telegram id handler
    BOT_API_HASH: str = "----------------------------"  # from telegram id handler
    BOT_API_TOKEN: str = "---------------------------------"  # from bot father
    PLATFORM: str = platform.system().lower()

    # Auther and bot version related variables
    BOT_AUTHORS: str = "@RULEROFCODES & @reverse_master"
    BOT_AVAILABILITY: str = "FREE_ALPHA_VERSION"
    BOT_NAME: str = "@reverse_master_bot"
    BOT_VERSION: float = 0.7

    # Temporary Directories related variables
    BASE_PATH: Path = Path(__file__).parent
    ALL_FILES_PATH: str = path.join(BASE_PATH, "TempBotDataFolders")
    DUMPER_PATH: str = path.join(ALL_FILES_PATH, "dumper_download_files")
    APK_PATH: str = path.join(ALL_FILES_PATH, "downloaded_apks")
    MODDING_PATH: str = path.join(ALL_FILES_PATH, "libs_to_mod")
    CONFIG_PATH: str = path.join(ALL_FILES_PATH, "processed_config_files")
    CRC_PATH: str = path.join(ALL_FILES_PATH, "crc_changed_files")
    COMBO_PATH: str = path.join(ALL_FILES_PATH, "created_combos_lists")
    SONGS_PATH: str = path.join(ALL_FILES_PATH, "youtube_downloaded_songs")
    PSEUDOCODE_PATH: str = path.join(ALL_FILES_PATH, "pseudocode_folder")
    AES_KEYS_PATH: str = path.join(ALL_FILES_PATH, "aes_keys_folder")

    # Some messages and limit variables
    ALLOWED_UPLOAD_MBS: int = 100
    BOT_STATICS_MESSAGE: str = f"**__[BOT STATICS]__**\n\n**--AUTHOR--**  **__-> {BOT_AUTHORS}__**\n\n" \
                               f"**--BOT_VERSION--**  **__-> {BOT_VERSION}__**\n" \
                               f"\n**--AVAILABLE_AS--**  **__-> {BOT_AVAILABILITY}__**"

    # Link Shorter options
    LINK_SHORTER_API_KEY: str = "edc01b5d741ff32f6c2d175a70dc6447"

    # Reverse engineering variable section
    MAX_CPU_PERCENTAGE: int = 50  # set to limit the cpu usage to percentage 50 (to reduce cpu stress)
    MAX_RAM_PERCENTAGE: int = 50  # set to limit the ram usage to percentage 50 (to reduce ram stress)

    DEX_TO_JAR_PATH: str = path.join(BASE_PATH, "ApkDecompilingTools", "dex2jar", "d2j-dex2jar.bat") \
        if PLATFORM == "windows" else path.join(BASE_PATH, "ApkDecompilingTools", "dex2jar", "d2j-dex2jar.sh")
    JD_CLI_PATH: str = path.join(BASE_PATH, "ApkDecompilingTools", "jd-cli", "jd-cli.bat") \
        if PLATFORM == "windows" else path.join(BASE_PATH, "ApkDecompilingTools", "jd-cli", "jd-cli")
    APK_TOOL_PATH: str = path.join(BASE_PATH, "ApkDecompilingTools", "apktool", "apktool.bat") \
        if PLATFORM == "windows" else path.join(BASE_PATH, "ApkDecompilingTools", "apktool", "apktool")

    TIME_OUT_FOR_COMMAND_EXECUTION: int = 120  # sec
    CPUS_AVAILABLE: int = psutil.cpu_count(logical=False)  # Use logical=False for physical cores only
    TOTAL_RAM_MEMORY: float = psutil.virtual_memory().available

    MAX_CPU_CORES: int = max(1, int(CPUS_AVAILABLE * (MAX_CPU_PERCENTAGE / 100)))
    MAX_RAM_BYTES: int = int(TOTAL_RAM_MEMORY * (MAX_RAM_PERCENTAGE / 100))
    MAX_BYTES_TO_MODIFY: int = 200

    MODIFICATION_OP_CODES: dict = {
        "cbnz": "cbz",
        "cbz": "cbnz",
        "movs": "mov",
        "beq": "bne",
        "bne": "beq"
    }

    # Dumper and PSEUDOCODE section variables
    DUMPER_REPLY_MESSAGE: str = "**__--[DUMPER MENU]--__**\n\n" \
                                "**imports**: __Dump all imports from the binary file.__\n" \
                                "**main_strings**: __Dump all main strings from the binary file.__\n" \
                                "**all_strings**: __Dump all types of strings from the binary file.__\n" \
                                "**linked_libraries**: __Dump linked libraries of the binary file.__\n" \
                                "**symbols**: __Dump symbols.__\n" \
                                "**ge_symbols**: __Dump G, E symbols.__\n" \
                                "**constructors_destructors**: __Dump only constructors and destructors.__\n" \
                                "**global_dump**: __Dump all possible information from the binary file.__"

    PSEUDOCODE_REPLY_MESSAGE: str = "**__--[PSEUDOCODE MENU]--__**\n\n" \
                                    "**decompile_main_function**: __Reverse the binary file and attempt to generate " \
                                    "the main CPP function.__\n\n" \
                                    "**decompile_complete_functions**: __Thoroughly reverse the entire file's " \
                                    "functions (time-consuming process-first 20 functions will be decompiled only).__"

    DUMPER_REPLY_MESSAGE_BUTTONS: list = [
        [
            "imports",
            "main_strings",
            "all_strings"
        ],
        [
            "linked_libraries",
            "symbols",
            "ge_symbols"
        ],
        [
            "constructors_destructors",
            "global_dump",
        ]
    ]

    PSEUDOCODE_REPLY_MESSAGE_BUTTONS: list = [
        [
            "decompile_main_function",
        ],
        [
            "decompile_complete_functions",
        ]
    ]

    # Key section variables
    KEY_COMBINATIONS: str = f"{string.ascii_letters}{string.digits}"
    GENERATED_KEYS_FILE_NAME: str = "generated_keys.json"
    KEY_FILE_NAME: str = "key_tokens.json"
    MINUTES_AFTER_KEY_EXPIRE: int = 39
    KEY_LENGTH: int = 30

    # Available command variables
    BOT_AVAILABLE_COMMANDS: dict = {
        "HELP/GREET": {
            "HI": "How can I help you today?"
        },
        "HELP SECTION": {
            "/help": "provides you help to use commands",
            "/start": "provides you help to use commands",
        },
        "KEY SECTION": {
            "/generate_key": "generate new key",
            "/set_key": "set generated key",
            "/time_left": "time to expire key",
        },
        "REVERSE-ENGINEERING SECTION": {
            "/dump": "dump data from libs",
            "/pseudocode": "Binary to C++ Transformation",
            "/decompile_apk": "apk into java source code",
            "/mod_lib": "creates anti-cheat libs .so files",
            "/crc32_changer": "change crc of files",
            "/aes_keys": "search in stored aes keys",
        },
        "HACKING SECTION": {
            "/gen_combo": "generate combos of service",
        },
        "GENERAL SECTION": {
            "/courses": "any courses on drive",
        },
        "MAX-UPLOADS": {
            "Max_length_file": f"less than {ALLOWED_UPLOAD_MBS}",
        }
    }

    # Other variables
    WELCOME_MESSAGE: str = "**" + "".join(
        [
            f"\n__--[{tag}]--__\n" +
            "\n".join(
                [
                    f"{cmd} - __{desc}__" for cmd, desc in commands.items()
                ]
            ) + "\n" for tag, commands in BOT_AVAILABLE_COMMANDS.items()
        ]
    ).strip() + "\n**"

    UNNECESSARY_CHARS: dict = {" ": "", "(": "_", ")": ""}
    TIME_OUT_ERROR_MESSAGE: str = "**Timeout for the current command. " \
                                  "Please reissue the command to submit required data again.**"
    FILE_NOT_LOCATED_ERROR: str = "An issue occurred: Unable to locate the downloaded file. " \
                                  "Please contact developers and report this bug"
    UNACCEPTED_ERROR: str = "An unexpected error occurred while attempting to reverse the binaries. " \
                            "Kindly reach out to the developer for more information regarding the error. "
    HELP_KEYBOARD_MENU: list = [
        [
            ('Telegram Channel', 'https://t.me/RulerKingCodes', 'url'),
            ('ReverseMaster', 'https://t.me/reverse_master', 'url')
        ],
        [
            ('RULEROFCODES', 'https://t.me/RULEROFCODES', 'url')
        ],
    ]


class EnableDisableFeatures(Enum):
    """
    Enum defining features and their availability status.

    Attributes:
        TEMP_BLOCK_MESSAGE (str): Temporary block message.
        IS_SHORT_GENERATED_LINK (bool): Flag for short generated link.

        ... (Other attributes)

        IS_DOWNLOAD_VIDIO_COMMAND_AVAILABLE (bool): Flag for the availability of the /download_vidio command.
    """

    # Others
    TEMP_BLOCK_MESSAGE: str = "This command is temporarily disabled. You can use other commands or contact the bot " \
                              "developers."
    IS_SHORT_GENERATED_LINK: bool = True

    # key section availability
    IS_GENERATE_KEY_COMMAND_AVAILABLE: bool = False
    IS_SET_KEY_COMMAND_AVAILABLE: bool = False
    IS_TIME_LEFT_COMMAND_AVAILABLE: bool = False

    # reverse engineering section availability
    IS_DUMP_COMMAND_AVAILABLE: bool = True
    IS_PSEUDOCODE_COMMAND_AVAILABLE: bool = True
    IS_DECOMPILE_APK_COMMAND_AVAILABLE: bool = True
    IS_MOD_LIB_COMMAND_AVAILABLE: bool = True
    IS_DECODE_INI_COMMAND_AVAILABLE: bool = True
    IS_ENCODE_INI_COMMAND_AVAILABLE: bool = True
    IS_CRC_CHANGER_COMMAND_AVAILABLE: bool = True
    IS_AES_KEY_COMMAND_AVAILABLE: bool = True

    # hacking section availability
    IS_GET_PROXY_COMMAND_AVAILABLE: bool = True
    IS_GET_COMBO_COMMAND_AVAILABLE: bool = True
    IS_PH_DETAILS_COMMAND_AVAILABLE: bool = True
    IS_IP_LOOKUP_COMMAND_AVAILABLE: bool = True
    IS_USERNAME_LOOKUP_COMMAND_AVAILABLE: bool = True
    IS_NAME_LOOKUP_COMMAND_AVAILABLE: bool = True
    IS_HOST_IP_COMMAND_AVAILABLE: bool = True
    IS_TWITTER_SCRAPER_COMMAND_AVAILABLE: bool = True
    IS_NMAP_COMMAND_AVAILABLE: bool = True
    IS_GEN_CC_COMMAND_AVAILABLE: bool = True

    # general section availability
    IS_COURSES_COMMAND_AVAILABLE: bool = True
    IS_GEN_MAIL_COMMAND_AVAILABLE: bool = True
    IS_DISPOSE_MAIL_COMMAND_AVAILABLE: bool = True
    IS_WEB_SEARCH_COMMAND_AVAILABLE: bool = True
    IS_DOWNLOAD_AUDIO_COMMAND_AVAILABLE: bool = True
    IS_DOWNLOAD_VIDIO_COMMAND_AVAILABLE: bool = True


class PreDefinedPipeCommands(Enum):
    """
    Enum defining predefined pipe commands for various operations.

    Attributes:
       REMOVING_FILE_PREFIX (str): Prefix for removing files based on platform.
       REMOVE_DUMPS (list): List of commands to remove dump files.
       REMOVE_PSEUDOCODE (list): List of commands to remove pseudocode files.

       ... (Other attributes)

       APK_DECOMPILING_TOOLS_PERMISSIONS (list): List of commands to set execution permissions for
                                                 APK decompiling tools.
    """

    # Removing files
    REMOVING_FILE_PREFIX: str = 'rm -rf' if GlobalVariables.PLATFORM.value != 'windows' else 'echo Y | del'
    REMOVE_DUMPS: list = [
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.DUMPER_PATH.value, "*.so")}"',
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.DUMPER_PATH.value, "*.txt")}"',
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.DUMPER_PATH.value, "*.bin")}"',
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.DUMPER_PATH.value, "*.exe")}"',
    ]

    REMOVE_PSEUDOCODE: list = [
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.PSEUDOCODE_PATH.value, "*.so")}"',
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.PSEUDOCODE_PATH.value, "*.cpp")}"',
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.PSEUDOCODE_PATH.value, "*.bin")}"',
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.PSEUDOCODE_PATH.value, "*.exe")}"',
    ]

    REMOVE_APKS: list = [
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.APK_PATH.value, "*.apk")}"',
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.BASE_PATH.value, "*_decompiled.zip")}"',
    ]

    REMOVE_MODS: list = [
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.MODDING_PATH.value, "*_functions.txt")}"',
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.MODDING_PATH.value, "*.so")}"',
    ]

    REMOVE_CRC_FILES: list = [
        f'{REMOVING_FILE_PREFIX} "{path.join(GlobalVariables.CRC_PATH.value, "*")}"',
    ]

    # Execution permission for linux os
    APK_DECOMPILING_TOOLS_PERMISSIONS: list = [
        f"chmod +x {GlobalVariables.DEX_TO_JAR_PATH.value}",
        f"chmod +x {GlobalVariables.JD_CLI_PATH.value}",
        f"chmod +x {GlobalVariables.APK_TOOL_PATH.value}",
    ]


class BotPrefixes(Enum):
    """
    Enum defining prefixes used by the bot.

    Attributes:
        DUMPER_IMPORTS_PREFIX (str): Prefix for imports dumped by the bot.
        BOT_MODDING_DETAILS (str): Modding details prefix.
        MODDING_TRANSITION (tuple): Modding transition details.
    """

    DUMPER_IMPORTS_PREFIX: str = f"[Imports Dumped by {GlobalVariables.BOT_NAME.value}]\n\n"
    BOT_MODDING_DETAILS: str = "**__--[Modding Details]--__**\n\n"
    MODDING_TRANSITION: tuple = (
        f"{BOT_MODDING_DETAILS}Trying:\nARCH_X86 \t MODE_32",
        f"{BOT_MODDING_DETAILS}Failed to apply:\nARCH_X86 \t MODE_32",
        f"{BOT_MODDING_DETAILS}Trying:\nARCH_X86 \t MODE_64",
        f"{BOT_MODDING_DETAILS}Failed to apply:\nARCH_X86 \t MODE_64",
        f"{BOT_MODDING_DETAILS}Trying:\nARCH_ARM \t MODE_THUMB",
        f"{BOT_MODDING_DETAILS}Binary is compatible with:\nARCH_ARM \t MODE_THUMB",
    )

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

from global_variables import GlobalVariables, EnableDisableFeatures, PreDefinedPipeCommands
from pyrogram.types import Message, ReplyKeyboardRemove
from asyncio.exceptions import TimeoutError
from pyromod import helpers, listen
from Utils.utils import Utilities
from sys import version_info
from pyrogram import Client
from os.path import isfile
from hashlib import md5
from struct import pack
from zlib import crc32


class CRCModification:
    """
    A class responsible for modifying CRC32 values in binary files.

    Attributes:
        _file_path (str): The path to the binary file.

    Methods:
        __init__(self, file_path: str): Initializes the CRCModification instance.
        crc32v2(self) -> int: Calculates the CRC32 value of the binary file.
        crc32_i(self) -> int: Gets the CRC32 value as an integer.
        crc32_s(self) -> str: Gets the CRC32 value as a hexadecimal string.
        i_tos(cls, i_hash) -> str: Converts an integer to a hexadecimal string.
        s_toi(cls, s_hash) -> int: Converts a hexadecimal string to an integer.
        calculate_new_contents(cls, target_crc, original_crc) -> int: Calculates the new CRC32 content.
        append_new_contents(cls, number) -> None: Appends new contents to the binary file.
        modify_crc(cls, target_crc) -> None: Modifies the CRC32 value of the binary file.
        get_md5(self) -> any([str, None]): Calculates the MD5 hash of the binary file.
        change_crc(cls, target_crc) -> str: Changes the CRC32 value of the binary file.
    """

    def __init__(self, file_path: str):
        """
        Initializes the CRCModification instance.

        Args:
            file_path (str): The path to the binary file.
        """

        self._file_path: str = file_path

    async def crc32v2(self) -> int:
        """
        Calculates the CRC32 value of the binary file.

        Returns:
            int: The CRC32 value.
        """

        open_file = open(self._file_path, "rb")
        crc = 0
        while True:
            buffer = open_file.read(1024 * 1024)
            if len(buffer) == 0:
                open_file.close()
                if version_info[0] < 3 and crc < 0:
                    crc += 2 ** 32
                return crc
            crc = crc32(buffer, crc)

    async def crc32_i(self) -> int:
        """
        Gets the CRC32 value as an integer.

        Returns:
            int: The CRC32 value as an integer.
        """

        i_hash = await self.crc32v2()
        if version_info[0] < 3 and i_hash < 0:
            i_hash += 2 ** 32
        return i_hash

    async def crc32_s(self) -> str:
        """
        Gets the CRC32 value as a hexadecimal string.

        Returns:
            str: The CRC32 value as a hexadecimal string.
        """

        i_hash = await self.crc32v2()
        if version_info[0] < 3 and i_hash < 0:
            i_hash += 2 ** 32
        s_hash = '%08X' % i_hash
        return s_hash

    @staticmethod
    async def i_tos(i_hash) -> str:
        """
        Converts an integer to a hexadecimal string.

        Args:
            i_hash: The integer value.

        Returns:
            str: The hexadecimal string.
        """

        return '%08X' % i_hash

    @staticmethod
    async def s_toi(s_hash) -> int:
        """
        Converts a hexadecimal string to an integer.

        Args:
            s_hash (str): The hexadecimal string.

        Returns:
            int: The integer value.
        """

        return int(s_hash, base=16)

    @staticmethod
    async def calculate_new_contents(target_crc, original_crc) -> int:
        """
        Calculates the new CRC32 content.

        Args:
            target_crc: The target CRC32 value.
            original_crc: The original CRC32 value.

        Returns:
            int: The new CRC32 content.
        """

        crc_poly = 0xEDB88320
        crc_inv = 0x5B358FD3
        final_xor = 0xFFFFFFFF

        target_crc ^= final_xor
        original_crc ^= final_xor
        new_crc_content = 0x00000000

        for i in range(0, 32):
            # reduce modulo crc_poly
            if (new_crc_content & 1) != 0:
                new_crc_content = (new_crc_content >> 1) ^ crc_poly
            else:
                new_crc_content >>= 1
            if (target_crc & 1) != 0:
                new_crc_content ^= crc_inv

            target_crc >>= 1

        new_crc_content ^= original_crc
        return new_crc_content

    async def append_new_contents(self, number) -> None:
        """
        Appends new contents to the binary file.

        Args:
            number: The new content to be appended.

        Returns:
            None
        """

        file_instance = open(self._file_path, 'ab')
        new_binaries = pack("<I", number)
        file_instance.write(new_binaries)
        file_instance.close()

    async def modify_crc(self, target_crc) -> None:
        """
        Modifies the CRC32 value of the binary file.

        Args:
            target_crc: The target CRC32 value.

        Returns:
            None
        """

        original_crc = await self.crc32_i()
        new_crc_content = await self.calculate_new_contents(target_crc, original_crc)
        await self.append_new_contents(new_crc_content)

    async def get_md5(self) -> any([str, None]):
        """
        Calculates the MD5 hash of the binary file.

        Returns:
            any([str, None]): The MD5 hash as a string or None if an error occurs.
        """

        try:
            md5_hash = md5()
            open_file = open(self._file_path, "rb")
            content = open_file.read()
            md5_hash.update(content)
            digest = md5_hash.hexdigest()
            open_file.close()
            return digest
        except Exception as e:
            return e

    async def change_crc(self, target_crc):
        """
        Changes the CRC32 value of the binary file.
        Args:
            target_crc: The target CRC32 value.
        Returns:
            str: A string containing details of the CRC32 change.
        """

        first_md5 = await self.get_md5()
        valid_target_crc: bool = True
        crc_max = int("FFFFFFFF", base=16)
        crc_min = int("00000000", base=16)
        target_crc_original = target_crc
        try:
            target_crc = int(target_crc_original, base=16)
            if target_crc > crc_max or target_crc < crc_min:
                valid_target_crc = False
        except Exception as e:
            valid_target_crc = False
            print(e)

        if valid_target_crc:
            if isfile(self._file_path):
                original_crc = await self.crc32_i()
                target_crc = int(target_crc_original, base=16)
                results1 = '**Original V32**: **__0x%s__**' % await self.i_tos(original_crc)
                results1 += f'\n**Original MD5**: **__{first_md5}__**\n\n'
                results1 += '**Target V32**:   **__0x%s__**' % await self.i_tos(target_crc)
                new_content = await self.calculate_new_contents(target_crc, original_crc)
                results1 += '\n**Four bytes to append (hex)**: **__0x%s__**' % await self.i_tos(new_content)
                await self.append_new_contents(new_content)
                final_crc = await self.crc32_i()
                results1 += '\n**Final V32**:    **__0x%s__**' % await self.i_tos(final_crc)
                results1 += f'\n**Final MD5**: **__{await self.get_md5()}__**'
                if final_crc == target_crc:
                    print('Modified the file with change in crc')
                    return results1
                else:
                    return 'Failed.'
            else:
                return "Input file inaccessible."
        else:
            return "Invalid target CRC-32."


class Crc32ChangerAPI(object):
    """
    A class providing an API for changing CRC32 values in binary files.

    Attributes:
        _app (Client): The Pyrogram Client instance.
        _utils (Utilities): An instance of the Utilities class for various utility functions.

    Methods:
        __init__(self, app: Client): Initializes the Crc32ChangerAPI instance.
        crc32changer(self, client: listen.Client, message: Message) -> None: Initiates the CRC32 changing process.
    """

    def __init__(self, app: Client):
        """
       Initializes the Crc32ChangerAPI instance.

       Args:
           app (Client): The Pyrogram Client instance.
       """

        self._app: Client = app
        self._utils: Utilities = Utilities(app=app)

    async def crc32changer(self, client: listen.Client, message: Message) -> None:
        """
        Initiates the CRC32 changing process.

        Args:
            client (listen.Client): The Pyrogram Client for handling communication.
            message (Message): The message object containing user input and context.

        Returns:
            None
        """

        if not EnableDisableFeatures.IS_CRC_CHANGER_COMMAND_AVAILABLE.value:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=EnableDisableFeatures.TEMP_BLOCK_MESSAGE.value,
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return

        # remove old files to free up space
        await self._utils.run_pipe_commands(commands_list=PreDefinedPipeCommands.REMOVE_CRC_FILES.value)
        file: any([None, tuple[str, str, str, str, any]]) = await self._utils.preprocess_file(
            client=client,
            message=message,
            caption='Send me any file.',
            download_directory=GlobalVariables.CRC_PATH.value,
            timeout=180
        )
        if not file:
            return
        new_name_with_path, old_name_with_path, file_name_without_ext, file_name_with_ext, user_file = file
        print(f"===============> CHANGING CRC32-{file_name_with_ext} <===============")
        file_instance = CRCModification(file_path=new_name_with_path)
        original_crc = await file_instance.crc32_i()
        try:
            new_crc_value: any = await client.ask(
                message.chat.id,
                text=f'Send new crc to modify. Current CRC value is (send only hex value)\n '
                     f'`0x{await file_instance.i_tos(original_crc)}`',
                timeout=180
            )
            new_crc_value: any = new_crc_value.text.strip()
        except TimeoutError:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=GlobalVariables.TIME_OUT_ERROR_MESSAGE.value,
                                                reply_markup=ReplyKeyboardRemove()
                                                )
            return

        new_crc_details: str = await file_instance.change_crc(target_crc=new_crc_value)
        try:
            await self._utils.send_document_files(
                client=client,
                message=message,
                document_path=new_name_with_path,
                caption_text=f"{GlobalVariables.BOT_STATICS_MESSAGE.value}\n\n**[DETAILS]**{new_crc_details}",
            )
        except ValueError as e:
            print(e)
            await self._utils.send_text_message(
                client=client,
                message=message,
                text=f"UNKNOWN ERROR: {new_crc_details}"
            )

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

from global_variables import GlobalVariables, EnableDisableFeatures, PreDefinedPipeCommands, BotPrefixes
from ReverseEngineeringSectionScripts.crc32_changer import CRCModification
from pyrogram.types import Message, ReplyKeyboardRemove
from asyncio.exceptions import TimeoutError
from pyromod import helpers, listen
from Utils.utils import Utilities
from pyrogram import Client
from os import path
import capstone
import keystone
import r2pipe


class ModifyBinaries(object):
    """
    A class responsible for modifying binary files through brute-force techniques.

    Attributes:
        _app (Client): The Pyrogram Client instance.
        _utils (Utilities): An instance of the Utilities class for various utility functions.

    Methods:
        __init__(self, app: Client): Initializes the ModifyBinaries instance.
        modify_binaries_by_brute_force(self, client: listen.Client, message: Message): Initiates the brute-force
        modification process for binary files.
        _start_modding(self, client: listen.Client, message: Message, binary_file_path: str, hex_addresses: list[str]):
        Initiates the actual modding process after receiving user inputs.
    """

    def __init__(self, app: Client):
        """
        Initializes the ModifyBinaries instance.

        Args:
            app (Client): The Pyrogram Client instance.
        """

        self._app: Client = app
        self._utils: Utilities = Utilities(app=app)

    async def modify_binaries_by_brute_force(self, client: listen.Client, message: Message) -> None:
        """
        Initiates the brute-force modification process for binary files.

        Args:
            client (listen.Client): The Pyrogram Client for handling communication.
            message (Message): The message object containing user input and context.

        Returns:
            None
        """

        if not EnableDisableFeatures.IS_MOD_LIB_COMMAND_AVAILABLE.value:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=EnableDisableFeatures.TEMP_BLOCK_MESSAGE.value,
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return

        # remove old files to free up space
        await self._utils.run_pipe_commands(commands_list=PreDefinedPipeCommands.REMOVE_MODS.value)
        file: any([None, tuple[str, str, str, str, any]]) = await self._utils.preprocess_file(
            client=client,
            message=message,
            caption='Send me any binary file (.exe, .bin, .so).',
            reply_markup=helpers.ikb(
                GlobalVariables.HELP_KEYBOARD_MENU.value),
            download_directory=GlobalVariables.MODDING_PATH.value,
            timeout=180
        )
        if not file:
            return
        new_name_with_path, old_name_with_path, file_name_without_ext, file_name_with_ext, user_file = file
        print(f"===============> MODDING LIB-{file_name_with_ext} <===============")
        file_info: any([str, None]) = await self._utils.run_subprocess_command(
            command=f"rabin2 -H {new_name_with_path}"
        )

        await self._utils.send_text_message(
            client=client,
            message=message,
            text=f"```Please wait we are analyzing binaries```\n\n**__[File Details]__**\n```{file_info}```"
        )
        reversing_pipe: any = r2pipe.open(filename=new_name_with_path)
        reversing_pipe.cmd(cmd="aa")
        functions_info = reversing_pipe.cmdj("aflj")
        function_file_path: str = path.join(path.dirname(new_name_with_path), f"{file_name_without_ext}_functions.txt")
        functions = [{"name": func["name"], "offset": func["offset"]} for func in functions_info]
        reversing_pipe.quit()
        with open(function_file_path, "w") as file:
            file.write("/*\nThis file is generated by @reverse_master_bot and is intended solely for "
                       "educational purposes.\nAny use of this file for illegal activities is "
                       "strictly prohibited.\n*/\n\n")
            for function in functions:
                offset = int(str(function['offset']), 16)
                file.write(f"0x{offset:08x} - {function['name']}\n")
            file.close()
        await self._utils.send_document_files(client=client,
                                              message=user_file,
                                              document_path=function_file_path,
                                              caption_text="Find functions you want to patch and send us their offers"
                                                           "Like that\n```0x012d\n0x0213e\n0x342e9d```"
                                              )
        try:
            hex_addresses: any = await client.ask(message.chat.id, 'Send me functions addresses', timeout=180)
            hex_addresses = hex_addresses.text.strip().split()
        except TimeoutError:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=GlobalVariables.TIME_OUT_ERROR_MESSAGE.value,
                                                reply_markup=ReplyKeyboardRemove()
                                                )
            return

        message_instance = await self._utils.send_text_message(
            client=client,
            message=message,
            text="Updates"
        )
        await self._utils.edit_send_message(message=message_instance, text=BotPrefixes.MODDING_TRANSITION.value,
                                            wait_for_some_time=3)

        await self._start_modding(client=client, message=message_instance,
                                  binary_file_path=new_name_with_path, hex_addresses=hex_addresses)

    async def _start_modding(self, client: listen.Client, message: Message,
                             binary_file_path: str, hex_addresses: list[str]) -> None:
        """
        Initiates the actual modding process after receiving user inputs.

        Args:
            client (listen.Client): The Pyrogram Client for handling communication.
            message (Message): The message object containing user input and context.
            binary_file_path (str): The path to the binary file to be modified.
            hex_addresses (list[str]): List of hex addresses corresponding to functions to be patched.

        Returns:
            None
        """
        file_instance = CRCModification(file_path=binary_file_path)
        original_crc = await file_instance.crc32_i()
        capstone_arch_arm = capstone.Cs(arch=capstone.CS_ARCH_ARM, mode=capstone.CS_MODE_THUMB)
        total_bytes_to_modify: list = []
        changeable_bytes: dict = {"addr": [], "code": []}
        open_file = open(file=binary_file_path, mode='rb')
        for function_address in hex_addresses:
            open_file.seek(int(function_address, base=16))
            total_bytes_to_modify.append(open_file.read(GlobalVariables.MAX_BYTES_TO_MODIFY.value))
        open_file.close()

        bytes_op_code_keys = GlobalVariables.MODIFICATION_OP_CODES.value.keys()
        capstone_modification_details: str = ""
        # Capstone reading and changing in bytes
        for current_byte in total_bytes_to_modify:
            bytes_index_in_list: int = total_bytes_to_modify.index(current_byte)
            for disassembled_byte in capstone_arch_arm.disasm(
                    code=current_byte,
                    offset=int(hex_addresses[bytes_index_in_list], 0)
            ):
                op_code = disassembled_byte.mnemonic.replace(" ", "")
                if op_code in bytes_op_code_keys:
                    capstone_modification_details += "%s \t %s \t %s\n" % (disassembled_byte.op_str,
                                                                           disassembled_byte.bytes,
                                                                           disassembled_byte.size)
                    new_op_code = bytes(("%s %s" % (disassembled_byte.mnemonic, disassembled_byte.op_str)
                                         ).replace(op_code, GlobalVariables.MODIFICATION_OP_CODES.value[op_code]),
                                        encoding="ASCII")
                    changeable_bytes["addr"].append(disassembled_byte.address)
                    changeable_bytes["code"].append(new_op_code)

        bytes_to_modify = {"addr": [], "bytes_to_mod": []}
        keystone_arch_arm = keystone.Ks(arch=keystone.KS_ARCH_ARM, mode=keystone.KS_MODE_THUMB)
        keystone_modification_details: str = ""
        total_bytes_modified: int = 0
        for instruction_address in changeable_bytes["addr"]:
            instruction_index = changeable_bytes["addr"].index(instruction_address)
            new_op_code = changeable_bytes['code'][instruction_index]
            op_code_encoded, number_of_statements = keystone_arch_arm.asm(string=new_op_code)
            if op_code_encoded:
                bytearray_buffer = bytearray(op_code_encoded)
                keystone_modification_details += "%s (number of statements: %u)\n" % (bytearray_buffer,
                                                                                      number_of_statements)
                total_bytes_modified += len(bytearray_buffer)
                bytes_to_modify["addr"].append(instruction_address)
                bytes_to_modify["bytes_to_mod"].append(bytearray_buffer)

        open_file = open(file=binary_file_path, mode='rb+')
        for address in bytes_to_modify["addr"]:
            index = bytes_to_modify["addr"].index(address)
            open_file.seek(address)
            open_file.write(bytes_to_modify["bytes_to_mod"][index])
        open_file.close()

        results: str = BotPrefixes.BOT_MODDING_DETAILS.value
        if total_bytes_modified > 0:
            new_crc_details: str = await file_instance.change_crc(target_crc=await file_instance.i_tos(original_crc))
            results += "**__[Total bytes changed]__**\n"
            results += f"**Total Bytes Modified**: **__--%d--__**" % total_bytes_modified
            results += f"\n\n**__[CRC Changing details]__**\n{new_crc_details}"
        else:
            results += "**__[Total bytes changed]__**\n"
            results += f"**Total Bytes Modified**: **__--%d--__**" % total_bytes_modified

        await self._utils.send_text_message(
            client=client,
            message=message,
            text=results
        )

        try:
            await self._utils.send_document_files(client=client,
                                                  message=message,
                                                  document_path=binary_file_path,
                                                  caption_text=GlobalVariables.BOT_STATICS_MESSAGE.value,
                                                  )
        except ValueError as e:
            print(e)
            await self._utils.send_text_message(
                client=client,
                message=message,
                text=f"The main function lacks a defined purpose for reversal. If the binary is encrypted, "
                     f"or in a corrupted state, the recommended course of action is to decrypt it using our "
                     f"proprietary memory dumper tool, which can be accessed here: "
                     f"\n\nhttps://github.com/Anonym0usWork1221/Memory-Dumper."
            )

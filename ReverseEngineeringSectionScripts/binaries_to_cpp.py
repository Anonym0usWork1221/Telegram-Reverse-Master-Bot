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
from pyrogram.types import Message, ReplyKeyboardMarkup, ReplyKeyboardRemove
from asyncio.exceptions import TimeoutError
from asyncio import AbstractEventLoop
from pyromod import helpers, listen
from Utils.utils import Utilities
from pyrogram import Client
from typing import IO
from os import path
import asyncio
import r2pipe


class PseudocodeHandler(object):
    """
    Windows:
        git clone https://github.com/wargio/r2dec-js
        cd r2dec-js\\p
        E:\\LinuxData\\Documents\\TelegramBotRecreation\\venv\\Scripts\\meson -Djsc_folder=".." build
        E:\\LinuxData\\Documents\\TelegramBotRecreation\\venv\\Scripts\\meson compile -C build
        E:\\LinuxData\\Documents\\TelegramBotRecreation\\venv\\Scripts\\ninja -C build install
    Linux:
        r2pm init
        r2pm install r2dec

    A class responsible for handling the de-compilation of binary files into pseudocode.

    Attributes:
        _app (Client): The Pyrogram Client instance.
        _utils (Utilities): An instance of the Utilities class for various utility functions.

    Methods:
        __init__(self, app: Client): Initializes the PseudocodeHandler instance.
        decompile_cpp_file(self, client: listen.Client, message: Message) -> None:
            Initiates the de-compilation process based on user input.
        _reverse_engineering_code(self, binary_path: str, target_path: str,
                                  reverse_main_function: bool = False) -> None:
            Asynchronously performs the reverse engineering of the binary code and generates pseudocode.
        _reverse_engineering_code_sync(binary_path: str, target_path: str,
                                       reverse_main_function: bool = False) -> None:
            Synchronously performs the reverse engineering of the binary code and generates pseudocode.
        _reversing_process(self, client: listen.Client, message: Message, download_file_path: str,
                           file_name_without_ext: str, pseudocode_file_name: str, command: str) -> None:
            Handles the overall process of decompiling binary code and sending the generated pseudocode.
    """

    def __init__(self, app: Client):
        """
        Initializes the PseudocodeHandler instance.

        Args:
            app (Client): The Pyrogram Client instance.
        """

        self._app: Client = app
        self._utils: Utilities = Utilities(app=app)

    async def decompile_cpp_file(self, client: listen.Client, message: Message) -> None:
        """
        Initiates the de-compilation process based on user input.

        Args:
            client (listen.Client): The Pyrogram Client for handling communication.
            message (Message): The message object containing user input and context.

        Returns:
            None
        """

        if not EnableDisableFeatures.IS_PSEUDOCODE_COMMAND_AVAILABLE.value:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=EnableDisableFeatures.TEMP_BLOCK_MESSAGE.value,
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return

        # remove old files to free up space
        await self._utils.run_pipe_commands(commands_list=PreDefinedPipeCommands.REMOVE_PSEUDOCODE.value)

        reply_keyboard: ReplyKeyboardMarkup = ReplyKeyboardMarkup(
            keyboard=GlobalVariables.PSEUDOCODE_REPLY_MESSAGE_BUTTONS.value,
            one_time_keyboard=True,
            resize_keyboard=True
        )
        await self._utils.reply_to_text_message(message=message,
                                                text=GlobalVariables.PSEUDOCODE_REPLY_MESSAGE.value,
                                                reply_markup=reply_keyboard
                                                )
        try:
            user_dumping_option: any = await client.ask(message.chat.id, 'Select an option.', timeout=180)
            user_dumping_option: any = user_dumping_option.text.strip()
        except TimeoutError:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=GlobalVariables.TIME_OUT_ERROR_MESSAGE.value,
                                                reply_markup=ReplyKeyboardRemove()
                                                )
            return

        options_mapping: dict = {
            "decompile_main_function": "aflj~main",
            "decompile_complete_functions": "aflj",
        }
        await self._utils.increment_in_usage_file()
        user_option: str = ""
        for option in options_mapping:
            if user_dumping_option == option:
                user_option = option
                break
        if user_option:
            file: any([None, tuple[str, str, str, str, any]]) = await self._utils.preprocess_file(
                client=client,
                message=message,
                caption='Send me any binary file (.exe, .bin, .so).',
                reply_markup=helpers.ikb(
                    GlobalVariables.HELP_KEYBOARD_MENU.value),
                download_directory=GlobalVariables.PSEUDOCODE_PATH.value,
                timeout=180
            )
            if not file:
                return
            new_name_with_path, old_name_with_path, file_name_without_ext, file_name_with_ext, user_file = file
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text="We are decomposing functions; "
                                                     "this may take a few minutes, depending on the load.",
                                                reply_markup=ReplyKeyboardRemove()
                                                )
            await self._reversing_process(client=client,
                                          message=user_file,
                                          download_file_path=new_name_with_path,
                                          file_name_without_ext=file_name_without_ext,
                                          pseudocode_file_name=user_option,
                                          command=options_mapping[user_option])
        else:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text="An unidentified message was sent.",
                                                reply_markup=ReplyKeyboardRemove()
                                                )
            return

    async def _reverse_engineering_code(self, binary_path: str, target_path: str,
                                        reverse_main_function: bool = False) -> None:
        """
        Asynchronously performs the reverse engineering of the binary code and generates pseudocode.

        Args:
            binary_path (str): The path to the binary file for reverse engineering.
            target_path (str): The path where the generated pseudocode will be saved.
            reverse_main_function (bool, optional): Flag indicating whether to reverse the main function only.
                                                     Defaults to False.

        Returns:
            None
        """

        loop: AbstractEventLoop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._reverse_engineering_code_sync,
                                          binary_path, target_path, reverse_main_function)

    @staticmethod
    def _reverse_engineering_code_sync(binary_path: str, target_path: str,
                                       reverse_main_function: bool = False) -> None:
        """
        Synchronously performs the reverse engineering of the binary code and generates pseudocode.

        Args:
            binary_path (str): The path to the binary file for reverse engineering.
            target_path (str): The path where the generated pseudocode will be saved.
            reverse_main_function (bool, optional): Flag indicating whether to reverse the main function only.
                                                     Defaults to False.

        Returns:
            None
        """

        reversing_pipe: any = r2pipe.open(filename=binary_path)
        reversing_pipe.cmd(cmd="aaa")  # analyze complete binary file

        if reverse_main_function:
            file_junks: str = "/*\nThis file is generated by @reverse_master_bot and is intended solely for " \
                              "educational purposes.\nAny use of this file for illegal activities is " \
                              "strictly prohibited.\n*/\n\n"
            reversing_pipe.cmd(cmd="af main")
            cplusplus_code: str = reversing_pipe.cmd(cmd=f"pdd").strip()  # making cpp code from binary
            cleaned_lines = [line for line in cplusplus_code.split("\n") if line.strip()]
            cplusplus_code = file_junks + "".join(cleaned_lines[2:])
            open_file: IO = open(file=target_path, mode="w")
            open_file.write(cplusplus_code)
            open_file.close()
        else:
            file_junks: str = "/*\nThis file is generated by @reverse_master_bot and is intended solely for " \
                              "educational purposes.\nAny use of this file for illegal activities is " \
                              "strictly prohibited.\n*/\n\n"

            all_functions: list = reversing_pipe.cmdj(cmd="aflj")
            for function in all_functions[:20]:  # only first 20 function
                function_address: str = function["offset"]
                cplusplus_code: str = reversing_pipe.cmd(cmd=f"pdd @{function_address}").strip()
                cleaned_lines = [line for line in cplusplus_code.split("\n") if line.strip()]
                if '#include' in file_junks:
                    cleaned_lines = cleaned_lines[3:]
                else:
                    cleaned_lines = cleaned_lines[2:]
                cplusplus_code = "".join(cleaned_lines) + "\n\n"
                file_junks += cplusplus_code

            open_file: IO = open(file=target_path, mode="w")
            open_file.write(file_junks)
            open_file.close()

    async def _reversing_process(self, client: listen.Client, message: Message, download_file_path: str,
                                 file_name_without_ext: str, pseudocode_file_name: str, command: str) -> None:
        """
        Handles the overall process of decompiling binary code and sending the generated pseudocode.

        Args:
           client (listen.Client): The Pyrogram Client for handling communication.
           message (Message): The message object containing user input and context.
           download_file_path (str): The path where the downloaded binary file is stored.
           file_name_without_ext (str): The name of the binary file without the extension.
           pseudocode_file_name (str): The type of pseudocode to generate (main function or all functions).
           command (str): The command to execute for pseudocode generation.

        Returns:
           None
        """

        print(f"===============> PSEUDOCODE-{pseudocode_file_name} <===============")
        pseudocode_file_path: str = path.join(path.dirname(download_file_path),
                                              f"{file_name_without_ext}_pseudocode.cpp")
        # this creates a file at dumping_file_path path

        file_information = await self._utils.run_subprocess_command(
            command=f"rabin2 -I {download_file_path}"
        )
        await self._utils.send_text_message(
            client=client,
            message=message,
            text=f"```I have initiated the Reversing Operation. Please take a seat, relax, and allow me "
                 f"to take charge from this point onward.``` \n\n**__--[FILE_INFO]--__**\n\n{file_information}"
        )

        await self._reverse_engineering_code(
            binary_path=download_file_path,
            target_path=pseudocode_file_path,
            reverse_main_function=True if command == "aflj~main" else False)

        try:
            await self._utils.send_document_files(client=client,
                                                  message=message,
                                                  document_path=pseudocode_file_path,
                                                  caption_text=GlobalVariables.BOT_STATICS_MESSAGE.value,
                                                  reply_markup=ReplyKeyboardRemove()
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

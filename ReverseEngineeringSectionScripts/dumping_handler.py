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
from pyromod import helpers, listen
from Utils.utils import Utilities
from pyrogram import Client
from os import path


class DumperHandler(object):
    """
    Handles the dumping of binary files and provides various dumping options.
    This class required Radare2 reverse engineering tool

    Windows Installation:
        (best download pre compiled binary https://github.com/radareorg/radare2/releases/tag/5.8.8)
        (or self compile down here)
        winget install -e --id Git.Git
        git clone https://github.com/radareorg/radare2
        radare2\\preconfigure.bat
        Note: if you are using virtual environment run this manually pathto/venv/python.exe -m pip install -UI pip ninja
        cd radare2
        configure.bat
        make.bat
        Note: if it gets issue with make.bat file use this command manually
        path\\to\\venv\\Scripts\\meson compile -C b

        # set the path to environment variable (make sure you are in admin rights when execute it)
        mklink /d C:\\Radare2Link %CD%\\prefix\\bin

        # add this path to environment variables (system PATH)
        C:\\Radare2Link

        (Note: After this you need to re-install requirements.txt file (pip install -r requirements.txt))

    Linux Installation:
        git clone https://github.com/radareorg/radare2
        sudo chmod 777 radare2/sys/install.sh
        radare2/sys/install.sh
    """

    def __init__(self, app: Client):
        """
        Initializes the DumperHandler.
        :param app: The Pyrogram Client instance.
        """

        self._app: Client = app
        self._utils: Utilities = Utilities(app=app)

    async def dumping_binary_files(self, client: listen.Client, message: Message) -> None:
        """
        Initiates the process of dumping binary files.

        :param client: The Pyrogram Client instance.
        :param message: The Pyrogram Message instance.
        """

        if not EnableDisableFeatures.IS_DUMP_COMMAND_AVAILABLE.value:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=EnableDisableFeatures.TEMP_BLOCK_MESSAGE.value,
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return

        # remove old files to free up space
        await self._utils.run_pipe_commands(commands_list=PreDefinedPipeCommands.REMOVE_DUMPS.value)

        reply_keyboard: ReplyKeyboardMarkup = ReplyKeyboardMarkup(
            keyboard=GlobalVariables.DUMPER_REPLY_MESSAGE_BUTTONS.value,
            one_time_keyboard=True,
            resize_keyboard=True
        )
        await self._utils.reply_to_text_message(message=message,
                                                text=GlobalVariables.DUMPER_REPLY_MESSAGE.value,
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

        options_mapping = {
            "imports": "-i",
            "main_strings": "-z",
            "all_strings": "-zzz",
            "linked_libraries": "-l",
            "symbols": "-s",
            "ge_symbols": "-E",
            "constructors_destructors": "-ee",
            "global_dump": "-g"
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
                download_directory=GlobalVariables.DUMPER_PATH.value,
                timeout=180
            )
            if not file:
                return
            new_name_with_path, old_name_with_path, file_name_without_ext, file_name_with_ext, user_file = file

            await self._dumping_process(client=client,
                                        message=user_file,
                                        download_file_path=new_name_with_path,
                                        file_name_without_ext=file_name_without_ext,
                                        dumping_file_name=user_option,
                                        command=options_mapping[user_option])
        else:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text="An unidentified message was sent.",
                                                reply_markup=ReplyKeyboardRemove()
                                                )
            return

    async def _dumping_process(self, client: listen.Client, message: Message, download_file_path: str,
                               file_name_without_ext: str, dumping_file_name: str, command: str) -> None:
        """
        Initiates the process of dumping based on the user's selection.

        :param client: The Pyrogram Client instance.
        :param message: The Pyrogram Message instance.
        :param download_file_path: The path of the downloaded file.
        :param file_name_without_ext: The name of the file without extension.
        :param dumping_file_name: The name of the dumping file.
        """

        print(f"===============> Dumping-{dumping_file_name} <===============")
        dumping_file_path: str = path.join(path.dirname(download_file_path),
                                           f"{file_name_without_ext}_{dumping_file_name}.txt")
        # this creates a file at dumping_file_path path

        await self._utils.run_subprocess_command(
            command=f"rabin2 {command} {download_file_path} > {dumping_file_path}",
            use_call=True
        )

        try:
            await self._utils.add_content_at_start_of_file(
                file_path=dumping_file_path,
                text=f"[This file is dumped By {GlobalVariables.BOT_NAME.value}]\n"
                     f"WARNING: Use this bot for ethical purposes only.\n\n"
            )
        except AttributeError as e:
            await self._utils.send_text_message(
                client=client,
                message=message,
                text=f"{GlobalVariables.UNACCEPTED_ERROR.value}ERROR_STATUS: AttributeError.",
                reply_markup=ReplyKeyboardRemove(),
                reply_to_message_id=False
            )
            print(f"ERROR in dumping_process: {e}")
            return

        await self._utils.send_document_files(client=client,
                                              message=message,
                                              document_path=dumping_file_path,
                                              caption_text=GlobalVariables.BOT_STATICS_MESSAGE.value,
                                              reply_markup=ReplyKeyboardRemove()
                                              )

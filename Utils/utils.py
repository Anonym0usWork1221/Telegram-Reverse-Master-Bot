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

from pyrogram.types import InlineKeyboardMarkup, ReplyKeyboardMarkup, Message, ReplyKeyboardRemove
from global_variables import GlobalVariables
from os import makedirs, path, popen, rename
from asyncio.exceptions import TimeoutError
from datetime import datetime
from typing import IO, AnyStr
from pyrogram import Client
from pyromod import listen
import subprocess
import asyncio
import random
import psutil


class Utilities(object):
    """
    Utility class for various helper functions.

    Args:
    - app (Client): The Pyrogram Client instance.

    Attributes:
    - _app (Client): The Pyrogram Client instance.
    - _usage_file_path (str): Path to the usage file.

    Methods:
    - validate_directories(): Creates necessary directories if they don't exist.
    - send_text_message(client, message, text, reply_to_message_id, reply_markup): Sends a text message.
    - generate_random_new_key(): Generates a random new key.
    - send_document_files(client, message, document_path, reply_to_message_id, caption_text, reply_markup): Sends document files.
    - reply_to_text_message(message, text, reply_markup): Replies to a text message.
    - edit_send_message(message, text, wait_for_some_time): Edits and sends multiple messages.
    - rename_file(old_name_with_path, new_name_with_path): Renames a file.
    - filter_file_name_with_removal_useless_char(file_path): Filters a file name by removing unnecessary characters.
    - progress_bar(current, total, old_message, downloading): Displays a progress bar in a message.
    - download_media_from_chat(client, message, file_path, check_extension): Downloads media from a chat.
    - increment_in_usage_file(): Increments the usage count in the usage file.
    - preprocess_file(client, message, caption, download_directory, reply_markup, timeout, filters): Preprocesses a file.
    - run_pipe_commands(commands_list): Runs a list of pipe commands.
    - add_content_at_start_of_file(file_path, text): Adds content at the start of a file.
    - run_subprocess_command(command, use_call): Runs a subprocess command.

    Note:
    - Uses Pyrogram library for Telegram bot functionalities.
    """

    def __init__(self, app: Client) -> None:
        """
        Initializes the Utilities class.

        Args:
        - app (Client): The Pyrogram Client instance.
        """

        self._app: Client = app
        self._usage_file_path: str = "usage.txt"
        self.validate_directories()

    @staticmethod
    def validate_directories() -> None:
        """
        Validates and creates necessary directories if they don't exist.
        """

        makedirs(name=GlobalVariables.ALL_FILES_PATH.value, exist_ok=True)
        makedirs(name=GlobalVariables.DUMPER_PATH.value, exist_ok=True)
        makedirs(name=GlobalVariables.APK_PATH.value, exist_ok=True)
        makedirs(name=GlobalVariables.MODDING_PATH.value, exist_ok=True)
        makedirs(name=GlobalVariables.CONFIG_PATH.value, exist_ok=True)
        makedirs(name=GlobalVariables.CRC_PATH.value, exist_ok=True)
        makedirs(name=GlobalVariables.COMBO_PATH.value, exist_ok=True)
        makedirs(name=GlobalVariables.SONGS_PATH.value, exist_ok=True)
        makedirs(name=GlobalVariables.PSEUDOCODE_PATH.value, exist_ok=True)
        makedirs(name=GlobalVariables.AES_KEYS_PATH.value, exist_ok=True)

    @staticmethod
    async def send_text_message(client: Client, message: Message, text: str, reply_to_message_id: bool = True,
                                reply_markup: any([InlineKeyboardMarkup, ReplyKeyboardRemove]) = None) -> Message:
        """
        Sends a text message.

        Args:
        - client (Client): The Pyrogram Client instance.
        - message (Message): The original message.
        - text (str): The text to be sent.
        - reply_to_message_id (bool): Whether to reply to the original message.
        - reply_markup (InlineKeyboardMarkup, ReplyKeyboardRemove): Reply markup for the message.

        Returns:
        - Message: The sent message.
        """

        return await client.send_message(
            chat_id=message.chat.id,
            text=text,
            reply_to_message_id=message.id if reply_to_message_id else None,
            reply_markup=reply_markup
        )

    @staticmethod
    async def generate_random_new_key() -> str:
        """
        Generates a random new key.

        Returns:
        - str: The generated random key.
        """

        return "".join(
            random.choice(GlobalVariables.KEY_COMBINATIONS.value) for _ in range(GlobalVariables.KEY_LENGTH.value)
        )

    async def send_document_files(self, client: Client, message: Message, document_path: str,
                                  reply_to_message_id: bool = True, caption_text: str = "",
                                  reply_markup: any([InlineKeyboardMarkup, ReplyKeyboardRemove]) = None) -> None:
        """
        Sends document files.

        Args:
        - client (Client): The Pyrogram Client instance.
        - message (Message): The original message.
        - document_path (str): The path to the document file.
        - reply_to_message_id (bool): Whether to reply to the original message.
        - caption_text (str): The caption text for the document.
        - reply_markup (InlineKeyboardMarkup, ReplyKeyboardRemove): Reply markup for the message.
        """

        # Replay markup will raise error due to unknown issue
        # https://github.com/pyrogram/pyrogram/issues/1056
        old_message = await self.send_text_message(client=client, message=message, text="Uploading - 0%.")

        uploading_start_time = datetime.now()
        await client.send_document(
            chat_id=message.chat.id,
            document=document_path,
            reply_to_message_id=message.id if reply_to_message_id else None,
            caption=caption_text if caption_text else "",
            progress=self.progress_bar,
            progress_args=(old_message, False),
            reply_markup=reply_markup
        )

        uploading_end_time = datetime.now()
        total_seconds = (uploading_end_time - uploading_start_time).seconds
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        await old_message.edit(f"**Upload Time: {hours} hours: {minutes} minutes :{seconds} seconds**")

    @staticmethod
    async def reply_to_text_message(message: Message, text: str, reply_markup: ReplyKeyboardMarkup = None) -> None:
        """
        Replies to a text message.

        Args:
        - message (Message): The original message.
        - text (str): The text to be replied with.
        - reply_markup (ReplyKeyboardMarkup): Reply markup for the message.
        """

        await message.reply(
            text=text,
            reply_markup=reply_markup
        )

    @staticmethod
    async def edit_send_message(message: Message, text: list, wait_for_some_time: int = None) -> None:
        """
        Edits and sends multiple messages.

        Args:
        - message (Message): The original message.
        - text (list): List of texts to be edited and sent.
        - wait_for_some_time (int): Optional delay between messages.
        """

        for msg in text:
            await message.edit(text=msg)
            if wait_for_some_time:
                await asyncio.sleep(delay=wait_for_some_time)

    @staticmethod
    async def rename_file(old_name_with_path: str, new_name_with_path: str) -> None:
        """
        Renames a file.

        Args:
        - old_name_with_path (str): The old file name with path.
        - new_name_with_path (str): The new file name with path.
        """

        rename(src=old_name_with_path, dst=new_name_with_path)

    @staticmethod
    async def filter_file_name_with_removal_useless_char(file_path: str) -> tuple[str, str]:
        """
        Filters a file name by removing unnecessary characters.

        Args:
        - file_path (str): The original file path.

        Returns:
        - tuple[str, str]: The filtered file path and file name.
        """

        for old_char, new_char in GlobalVariables.UNNECESSARY_CHARS.value.items():
            file_path = file_path.replace(old_char, new_char)  # with no special characters

        file_name = path.splitext(path.basename(file_path))[0]  # with no extension
        return file_path, file_name

    @staticmethod
    async def progress_bar(current: int, total: int, old_message: Message, downloading: bool = True):
        """
        Displays a progress bar in a message.

        Args:
        - current (int): The current progress value.
        - total (int): The total progress value.
        - old_message (Message): The original message to be edited.
        - downloading (bool): Whether it's downloading or uploading.
        """

        total_downloaded = f"{current * 100 / total:.1f}%"
        if downloading:
            downloading_message: str = "Downloading"
        else:
            downloading_message: str = "Uploading"

        await old_message.edit(f"__{downloading_message} - {total_downloaded}__")

    async def download_media_from_chat(self,
                                       client: Client,
                                       message: Message,
                                       file_path: str,
                                       check_extension: list = None) \
            -> any(
                [
                    tuple[str, str],
                    tuple[None, None]
                ]
            ):
        """
        Downloads media from a chat.

        Args:
        - client (Client): The Pyrogram Client instance.
        - message (Message): The original message.
        - file_path (str): The path to save the downloaded file.
        - check_extension (list): List of valid file extensions.

        Returns:
        - tuple[str, str] or tuple[None, None]: The downloaded file information or None if there's an error.
        """

        old_message = await self.send_text_message(client=client, message=message, text="Downloading - 0%.")

        download_start_time = datetime.now()
        downloaded_file_path = await self._app.download_media(
            message=message,
            file_name=f"{file_path}/",  # pyrogram detect / and consider it path and save file with original name
            progress=self.progress_bar,
            progress_args=(old_message, True),
        )
        download_end_time = datetime.now()
        total_seconds = (download_end_time - download_start_time).seconds
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        await old_message.edit(f"Download Time: {hours} hours: {minutes} minutes :{seconds} seconds")

        file_name = path.basename(downloaded_file_path)
        if check_extension:
            valid_extension = any(file_name.lower().endswith(ext.lower()) for ext in check_extension)
            if not valid_extension:
                await self.send_text_message(client=client, message=message,
                                             text=f"Please provide only the following file extensions: "
                                                  f"{', '.join(check_extension)}.")
                return None, None

        directory_path: str = path.dirname(downloaded_file_path)
        return file_name, directory_path

    async def increment_in_usage_file(self) -> None:
        """
        Increments the usage count in the usage file.
        """

        if not path.isfile(self._usage_file_path):
            open_file = open(self._usage_file_path, "w")
            open_file.write("1")
            open_file.close()
        else:
            open_file = open(self._usage_file_path, "r")
            old_number_of_usage = int(open_file.read())
            open_file.close()

            open_file = open(self._usage_file_path, "w")
            open_file.write(str(old_number_of_usage + 1))
            open_file.close()

    async def preprocess_file(self, client: listen.Client,
                              message: Message,
                              caption: str,
                              download_directory: str,
                              reply_markup: any([InlineKeyboardMarkup, None]) = None,
                              timeout: int = 180,
                              filters=None,
                              check_extension: list[str] = None
                              ) -> any([None, tuple[str, str, str, str, any]]):

        """
        Preprocesses a file.

        Args:
        - client (Client): The Pyrogram Client instance.
        - message (Message): The original message.
        - caption (str): The caption for the file.
        - download_directory (str): The directory to save the downloaded file.
        - reply_markup (InlineKeyboardMarkup, None): Reply markup for the message.
        - timeout (int): Timeout for user interaction.
        - filters: Filters for user interaction.
        - check_extension: Match extensions in downloaded file

        Returns:
        - tuple[str, str, str, str, any] or None: The preprocessed file information or None if there's an error.
        """

        try:
            user_file: any = await client.ask(chat_id=message.chat.id, text=caption, timeout=timeout, filters=filters)
        except TimeoutError:
            await self.send_text_message(client=client,
                                         message=message,
                                         text=GlobalVariables.TIME_OUT_ERROR_MESSAGE.value,
                                         reply_markup=ReplyKeyboardRemove()
                                         )
            return None

        file_name, downloaded_file_path = await self.download_media_from_chat(
            client=client, message=user_file, file_path=download_directory, check_extension=check_extension
        )

        if not file_name or not downloaded_file_path:
            await self.send_text_message(client=client,
                                         message=user_file,
                                         text=GlobalVariables.FILE_NOT_LOCATED_ERROR.value,
                                         reply_markup=reply_markup if reply_markup else None
                                         )
            return None

        # removed some characters like (whitespaces) etc. for making file operation clear
        file_name_with_ext, file_name_without_ext = await self.filter_file_name_with_removal_useless_char(
            file_path=file_name
        )

        # rename file with clean characters
        new_name_with_path: str = path.join(downloaded_file_path, file_name_with_ext)
        old_name_with_path: str = str(path.join(downloaded_file_path, file_name))
        await self.rename_file(old_name_with_path=old_name_with_path, new_name_with_path=new_name_with_path)
        return new_name_with_path, old_name_with_path, file_name_without_ext, file_name_with_ext, user_file

    @staticmethod
    async def run_pipe_commands(commands_list: list) -> None:
        """
        Runs a list of pipe commands.

        Args:
        - commands_list (list): List of pipe commands to be executed.
        """

        for command in commands_list:
            popen(command)

    @staticmethod
    async def add_content_at_start_of_file(file_path: str, text: str) -> None:
        """
        Adds content at the start of a file.

        Args:
        - file_path (str): The path to the file.
        - text (str): The text to be added at the start.
        """

        open_file: IO = open(file=file_path, mode="r+")
        previous_content: AnyStr = open_file.read()
        open_file.seek(0)  # point to start
        open_file.write(f"{text}\n{previous_content}")
        open_file.close()

    @staticmethod
    async def run_subprocess_command(command: str, use_call: bool = False) -> any([str, None]):
        """
        Runs a subprocess command.

        Args:
        - command (str): The subprocess command to be executed.
        - use_call (bool): Whether to use subprocess.call instead of asyncio.create_subprocess_exec.

        Returns:
        - str or None: The output of the command or None if there's an error.
        """

        if not use_call:
            try:
                command_list: list = command.split()  # make words list
                process: asyncio.subprocess.Process
                if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy') and \
                        asyncio.WindowsSelectorEventLoopPolicy().get_event_loop() is not None:
                    # Running on Windows (preexec_fn is not supported on Windows)
                    process = await asyncio.create_subprocess_exec(
                        *command_list,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                else:
                    # Running on a Unix-based system
                    process = await asyncio.create_subprocess_exec(
                        *command_list,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        preexec_fn=lambda: (
                            psutil.Process().cpu_affinity(list(range(GlobalVariables.MAX_CPU_CORES.value))),
                            psutil.Process().memory_percent() < GlobalVariables.MAX_RAM_PERCENTAGE.value
                        ),
                        start_new_session=True
                    )
                stdout, stderr = await asyncio.wait_for(process.communicate(),
                                                        timeout=GlobalVariables.TIME_OUT_FOR_COMMAND_EXECUTION.value)
                return stdout.decode('utf-8') if stdout.decode('utf-8') else "Command returned nothing"
            except asyncio.TimeoutError:
                print("Command execution timed out.")
                return None
        else:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: subprocess.call(args=command, shell=True))
            return None

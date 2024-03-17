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

from global_variables import GlobalVariables, EnableDisableFeatures
from KeySectionScripts.api_key_request import request_new_key
from asyncio.exceptions import TimeoutError
from pyromod import helpers, listen
from pyrogram.types import Message
from Utils.utils import Utilities
from pyrogram import Client
from typing import IO
from os import path
import json
import time


class KeysHandler(object):
    """
    Handles key generation, registration, and expiration checks.
    """

    def __init__(self, app: Client) -> None:
        """
        Initializes the KeysHandler instance.

        Parameters:
        - `app`: A Pyrogram Client instance.
        """

        self._app: Client = app
        self._utils: Utilities = Utilities(app=app)

    async def generate_new_key(self, client: Client, message: Message) -> None:
        """
        Generates a new key and updates the corresponding files.

        Parameters:
        - `client`: A Pyrogram Client instance.
        - `message`: The message that triggered the key generation.
        """

        # If developer disabled this feature
        if not EnableDisableFeatures.IS_GENERATE_KEY_COMMAND_AVAILABLE.value:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=EnableDisableFeatures.TEMP_BLOCK_MESSAGE.value,
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return

        chat_id: str = str(message.chat.id)
        open_file: IO = open(GlobalVariables.KEY_FILE_NAME.value, "r")
        current_keys: dict = json.load(fp=open_file)
        open_file.close()
        await self._utils.send_text_message(client=client,
                                            message=message,
                                            text="Please wait; your key generation is in progress.")
        generated_key: str = await self._utils.generate_random_new_key()
        print(f"===============> GENERATED KEY-{generated_key} <===============")
        generated_key_url: str = await request_new_key(generated_key=generated_key)  # key generation mechanism
        if not generated_key_url:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text="Unable to create a new key for you. Please contact developers "
                                                     "and report the bug.",
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return
        if not path.isfile(GlobalVariables.GENERATED_KEYS_FILE_NAME.value):
            json.dump(obj={}, fp=open(file=GlobalVariables.GENERATED_KEYS_FILE_NAME.value, mode="w"))
            generated_keys: dict = {}
        else:
            generated_keys: dict = json.load(fp=open(file=GlobalVariables.GENERATED_KEYS_FILE_NAME.value, mode="r"))

        generated_keys[generated_key] = time.time()
        json.dump(obj=generated_keys, fp=open(file=GlobalVariables.GENERATED_KEYS_FILE_NAME.value, mode="w"))
        response_text = f"Your {'re-' if chat_id in current_keys.keys() else 'first '}" \
                        f"key has been {'re-' if chat_id in current_keys.keys() else ''}" \
                        f"generated successfully.\n{generated_key_url}"
        await self._utils.send_text_message(client=client,
                                            message=message,
                                            text=response_text)
        print(response_text)  # as a debugging message

    async def register_new_key(self, client: listen.Client, message: Message) -> None:
        """
        Registers a new key provided by the user.

        Parameters:
        - `client`: A Pyrogram listen.Client instance.
        - `message`: The message containing the key registration request.
        """
        if not EnableDisableFeatures.IS_SET_KEY_COMMAND_AVAILABLE.value:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=EnableDisableFeatures.TEMP_BLOCK_MESSAGE.value,
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return

        if not path.isfile(GlobalVariables.GENERATED_KEYS_FILE_NAME.value):
            json.dump(obj={}, fp=open(file=GlobalVariables.GENERATED_KEYS_FILE_NAME.value, mode="w"))
            registered_keys: dict = {}
        else:
            registered_keys: dict = json.load(fp=open(file=GlobalVariables.GENERATED_KEYS_FILE_NAME.value, mode="r"))

        if not path.isfile(GlobalVariables.KEY_FILE_NAME.value):
            json.dump(obj={}, fp=open(file=GlobalVariables.KEY_FILE_NAME.value, mode="w"))
            current_keys: dict = {}
        else:
            current_keys: dict = json.load(fp=open(file=GlobalVariables.KEY_FILE_NAME.value, mode="r"))

        # this function is inherited from pyrogram listen module
        try:
            user_passed_key: any = await client.ask(message.chat.id, 'Send key to register.', timeout=180)
            user_passed_key: any = user_passed_key.text.strip()
        except TimeoutError:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=GlobalVariables.TIME_OUT_ERROR_MESSAGE.value)
            return

        print(f"===============> REGISTER KEY-{user_passed_key} <===============")

        if user_passed_key in registered_keys:
            chat_id: str = str(message.chat.id)
            generation_time: float = registered_keys.pop(user_passed_key)
            json.dump(obj=registered_keys, fp=open(file=GlobalVariables.GENERATED_KEYS_FILE_NAME.value, mode="w"))

            time_gap = int(time.time() - generation_time)
            remaining_minutes: int = GlobalVariables.MINUTES_AFTER_KEY_EXPIRE.value - int(time_gap // 60)

            if 0 <= remaining_minutes <= GlobalVariables.MINUTES_AFTER_KEY_EXPIRE.value:
                current_keys[chat_id] = generation_time
                json.dump(obj=current_keys, fp=open(file=GlobalVariables.KEY_FILE_NAME.value, mode="w"))
                await self._utils.send_text_message(client=client,
                                                    message=message,
                                                    text="Your key has been updated successfully")
            else:
                await self._utils.send_text_message(client=client,
                                                    message=message,
                                                    text="Your key is expired, please generate a "
                                                         "new one using /generate_key")
        else:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text="Your key is invalid, please generate a "
                                                     "new one using /generate_key")

    async def calculate_key_remaining_time(self, client: Client, message: Message) -> None:
        """
        Calculates and informs the user about the remaining time for their registered key.

        Parameters:
        - `client`: A Pyrogram Client instance.
        - `message`: The message that triggered the key expiration check.
        """

        # If developer disabled this feature
        if not EnableDisableFeatures.IS_TIME_LEFT_COMMAND_AVAILABLE.value:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=EnableDisableFeatures.TEMP_BLOCK_MESSAGE.value,
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return

        # check for the file
        if not path.isfile(GlobalVariables.KEY_FILE_NAME.value):
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text="You do not have a registered key.")
            open_file: IO = open(GlobalVariables.KEY_FILE_NAME.value, "w")
            json.dump(obj={}, fp=open_file)
            open_file.close()
            return

        current_message_id: str = str(message.chat.id)
        open_file: IO = open(GlobalVariables.KEY_FILE_NAME.value, "r")
        current_keys: dict = json.load(fp=open_file)
        open_file.close()

        # if key found in generated keys
        if current_message_id in current_keys.keys():
            time_of_key_generation: float = current_keys[current_message_id]
            time_gap: float = time.time() - time_of_key_generation
            remaining_minutes: int = GlobalVariables.MINUTES_AFTER_KEY_EXPIRE.value - int(time_gap // 60)

            print(f"===============> REMAINING TIME-{remaining_minutes} <===============")
            # if key is not expired yet
            if 0 <= remaining_minutes <= GlobalVariables.MINUTES_AFTER_KEY_EXPIRE.value:
                await self._utils.send_text_message(client=client,
                                                    message=message,
                                                    text=f"{remaining_minutes} minutes left for your key to expire"
                                                    )
            # if key is expired
            else:
                await self._utils.send_text_message(client=client,
                                                    message=message,
                                                    text="Your key has expired. Please generate a new one."
                                                    )

            return

        # if key is not in generated keys
        await self._utils.send_text_message(client=client,
                                            message=message,
                                            text="You do not have a registered key.")

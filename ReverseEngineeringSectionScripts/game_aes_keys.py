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
from pyrogram.types import Message, ReplyKeyboardRemove
from CommonSectionScripts.randomuser import users
from asyncio.exceptions import TimeoutError
from pyromod import helpers, listen
from Utils.utils import Utilities
from random import choice, randint
from bs4 import BeautifulSoup
from json import loads, dump
from pyrogram import Client
from os import path
from requests import get
from re import compile


class AESKeysAPI(object):
    """
    A class providing an API for retrieving AES keys for games.

    Attributes:
        _app (Client): The Pyrogram Client instance.
        _utils (Utilities): An instance of the Utilities class for various utility functions.
        _aes_keys_file_name (str): The path to the file containing AES keys.

    Methods:
        __init__(self, app: Client): Initializes the AESKeysAPI instance.
        _get_aes_keys(self) -> dict: Retrieves AES keys from the web or cached file.
        aes_key(self, client: listen.Client, message: Message) -> None: Retrieves and sends AES keys for a game.
    """

    def __init__(self, app: Client):
        """
        Initializes the AESKeysAPI instance.

        Args:
            app (Client): The Pyrogram Client instance.
        """

        self._app: Client = app
        self._utils: Utilities = Utilities(app=app)
        self._aes_keys_file_name: str = path.join(GlobalVariables.AES_KEYS_PATH.value, 'games_aes_keys.json')

    async def _get_aes_keys(self) -> dict:
        """
        Retrieves AES keys from the web or cached file.

        Returns:
            dict: A dictionary containing AES keys.
        """

        if randint(0, 1000) != 500 and path.isfile(self._aes_keys_file_name):
            keys_data_read = open(self._aes_keys_file_name, "r").read()
            current_keys = loads(keys_data_read)
            return current_keys

        url = "https://cs.rin.ru/forum/viewtopic.php?f=10&t=100672"
        pattern = compile("(0x)[A-F0-9]+")

        payloads = {
            "f": "10",
            "t": "100672"
        }

        request_headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,"
                      "*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "cookie": "",
            "upgrade-insecure-requests": "1",
            "user-agent": choice(users)
        }

        response = get(url, headers=request_headers, data=payloads)
        soup = BeautifulSoup(response.content, parser="html.parser", features="lxml")
        raw_classes = soup.find("div", "text")

        current_aes_keys = {}
        for raw_data in raw_classes.find_all("li"):
            raw_key = raw_data.text
            if " " in raw_key:
                raw_aes_key = raw_key.rsplit(" ", 1)
            else:
                raw_aes_key = raw_key.rsplit(" ", 1)

            if pattern.match(raw_aes_key[1]):
                current_aes_keys[raw_aes_key[0].strip()] = raw_aes_key[1].strip()
            else:
                pass

        dump(current_aes_keys, open(self._aes_keys_file_name, "w"))
        return current_aes_keys

    async def aes_key(self, client: listen.Client, message: Message) -> None:
        """
        Retrieves and sends AES keys for a game.

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

        try:
            key_search_value: any = await client.ask(
                message.chat.id,
                text='Please enter the name of the game (e.g., Ace Combat).',
                timeout=180
            )
            key_search_value: any = key_search_value.text.strip()
        except TimeoutError:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=GlobalVariables.TIME_OUT_ERROR_MESSAGE.value,
                                                reply_markup=ReplyKeyboardRemove()
                                                )
            return

        await self._utils.send_text_message(client=client,
                                            message=message,
                                            text=f"Retrieving keys (may take some time): {key_search_value}")

        print(f"===============> GETTING AES KEY-{key_search_value} <===============")
        current_keys: dict = await self._get_aes_keys()
        output_formatted = "**__"
        found_data = False
        for aes_key_title, aes_key_value in current_keys.items():
            if key_search_value.lower() in aes_key_title.lower():
                output_formatted += f"{aes_key_title}\n`{aes_key_value}`\n\n"
                found_data = True
        if not found_data:
            output_formatted += f"No data found for: {key_search_value}"
        output_formatted += "__**"

        await self._utils.send_text_message(client=client,
                                            message=message,
                                            text=output_formatted)



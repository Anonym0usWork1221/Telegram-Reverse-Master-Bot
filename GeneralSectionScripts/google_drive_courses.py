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
from requests.exceptions import RequestException
from asyncio.exceptions import TimeoutError
from requests_html import AsyncHTMLSession
from pyromod import listen, helpers
from urllib.parse import quote_plus
from Utils.utils import Utilities
from requests import Response
from pyrogram import Client
from random import choice


class GoogleDriveScraper(object):
    """
    GoogleDriveScraper Class

    This class provides functionality to scrape Google Drive links for courses based on user queries.

    Attributes:
        _app (Client): The Pyrogram Client instance.
        _utils (Utilities): An instance of the Utilities class for common utility functions.
    """

    def __init__(self, app: Client):
        """
        Initialize GoogleDriveScraper.

        Args:
            app (Client): The Pyrogram Client instance.
        """

        self._app: Client = app
        self._utils: Utilities = Utilities(app=app)

    @staticmethod
    async def __get_source(url) -> any([Response, None]):
        """
        Get the HTML response from the specified URL.

        Args:
            url (str): The URL to fetch.

        Returns:
            any: The HTML response as a Response object or None if an error occurs.
        """

        try:
            session = AsyncHTMLSession()
            response = await session.get(url, headers={"user-agent": choice(users)})
            return response
        except RequestException as e:
            print("[-] Request Exception on (get_source): ", e)
            return None

    async def scrape_google_drive(self, client: listen.Client, message: Message) -> None:
        """
        Scrape Google Drive links based on user input and send the results to the user.

        Args:
            client (listen.Client): The Pyrogram Client instance for listening.
            message (Message): The message object representing the user's input.
        """

        if not EnableDisableFeatures.IS_COURSES_COMMAND_AVAILABLE.value:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=EnableDisableFeatures.TEMP_BLOCK_MESSAGE.value,
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return

        try:
            target_query: any = await client.ask(
                message.chat.id,
                text='Please search for the course you want, such as Python video courses.',
                timeout=180
            )
            target_query: any = target_query.text.strip()
        except TimeoutError:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=GlobalVariables.TIME_OUT_ERROR_MESSAGE.value,
                                                reply_markup=ReplyKeyboardRemove()
                                                )
            return

        print(f"===============> SEARCHING COURSE-{target_query} <===============")
        await self._utils.send_text_message(client=client, message=message,
                                            text=f'Courses are currently being fetched for the query '
                                                 f'{target_query}. Please wait.')

        query = quote_plus(f"{target_query} site:drive.google.com")
        response = await self.__get_source(f"https://www.google.co.uk/search?q={query}")
        if not response:
            await self._utils.send_text_message(client=client, message=message,
                                                text='UNKNOWN ERROR: unable to fetch courses. '
                                                     'If error persists, try contact an administrator.')
            return

        search_results = response.html.find(selector='div[class*="tF2Cxc"][lang="en"]')
        output = {"titles": [], "links": []}
        for result in search_results:
            title = result.find(selector="h3", first=True)
            link = result.find(selector='div[class="yuRUbf"] a', first=True)
            if title and link:
                output["titles"].append(title.text)
                output["links"].append(link.attrs['href'])

        total_links = len(output["links"])
        if total_links <= 0:
            await self._utils.send_text_message(client=client, message=message,
                                                text='Sorry, no search results were found for your query.'
                                                     ' Please try again after few minutes.')
            return

        output_format = ""
        if total_links >= 11:
            for index in range(0, 10):
                output_format += f"**__{output['titles'][index]}__**\n__{output['links'][index]}__\n\n"
        else:
            for index in range(0, total_links):
                output_format += f"**__{output['titles'][index]}__**\n__{output['links'][index]}__\n\n"

        await self._utils.send_text_message(client=client, message=message, text=output_format)

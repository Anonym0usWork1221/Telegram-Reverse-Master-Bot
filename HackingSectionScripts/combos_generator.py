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
from os import path
from random import choice
from re import match


class CombosGenerator(object):
    """
    A class responsible for generating combo lists for various services.

    Attributes:
        __additional_list_to_scrape (tuple): A tuple containing additional URLs to scrape for combo lists.

    Methods:
        __init__(self, app: Client): Initialize the CombosGenerator instance.
        __get_source(url): Retrieves the HTML source of a given URL.
        __scrape_google_links(query: str) -> list: Scrapes Google search results for combo list links.
        __scrape_paste_fo(url: str) -> dict: Scrapes combo lists from paste.fo.
        __scrape_pastebin_pl(url: str, total_pages: int) -> dict: Scrapes combo lists from pastebin.pl.
        __clean_email_list(string_text: str) -> list[str]: Cleans and validates email lists from a raw text.
        _get_combos_file(query: str) -> any([str, None]): Fetch combo lists based on a given query.
        __filter_and_clean_links(links_data: dict, query: str) -> list[str]: Filters and cleans combo list links.
        generate_combos(self, client: listen.Client, message: Message) -> None: Initiates the combo list generation process.
    """

    __additional_list_to_scrape: tuple = (
        'https://paste.fo/user/Snakyyy10',
        'https://paste.fo/recent',
        'https://paste.fo/top',
        'https://paste.fo/user/Kuvira',
        'https://paste.fo/user/wizard460',
        'https://paste.fo/user/MultipleCase',
        'https://paste.fo/user/Erasuz',
        'https://paste.fo/user/Night',
        'https://paste.fo/user/CDSG',
        'https://paste.fo/user/Ddarknotevil',
        'https://paste.fo/user/weight',
        'https://paste.fo/user/txz'
    )

    def __init__(self, app: Client):
        """
        Initializes the CombosGenerator instance.

        Args:
           app (Client): The Pyrogram Client instance.
        """

        self._app: Client = app
        self._utils: Utilities = Utilities(app=app)

    @staticmethod
    async def __get_source(url) -> any([Response, None]):
        """
        Retrieves the HTML source of a given URL.

        Args:
            url: The URL to retrieve an HTML source from.

        Returns:
            any([Response, None]): The HTTP response or None if an exception occurs.
        """

        try:
            session = AsyncHTMLSession()
            response = await session.get(url, headers={"user-agent": choice(users)})
            return response
        except RequestException as e:
            print("[-] Request Exception on (get_source): ", e)
            return None

    async def __scrape_google_links(self, query: str) -> list:
        """
        Scrapes Google search results for combo list links.

        Args:
            query (str): The search query.

        Returns:
            list: A list of filtered combo list links.
        """

        query = quote_plus(query)
        response = await self.__get_source(f"https://www.google.co.uk/search?q={query}")
        links = list(response.html.absolute_links)
        links_set = set()
        google_domains = ('https://www.google.',
                          'https://google.',
                          'https://webcache.googleusercontent.',
                          'http://webcache.googleusercontent.',
                          'https://policies.google.',
                          'https://support.google.',
                          'https://maps.google.')

        for url in links[:]:
            if not url.startswith(google_domains):
                links_set.add(url)
        return list(links_set)

    async def __scrape_paste_fo(self, url: str) -> dict:
        """
        Scrapes combo lists from paste.fo.

        Args:
            url (str): The URL to scrape from.

        Returns:
            dict: A dictionary containing titles and links of combo lists.
        """

        response = await self.__get_source(url)
        css_identifier_result = ".pastelist tr"
        css_identifier_link = "td a"
        results = response.html.find(css_identifier_result)
        output = {"titles": [], "links": []}
        for result in results:
            details = result.find(css_identifier_link, first=True)
            if details:
                output["titles"].append(details.text)
                raw_link = details.absolute_links.pop().replace("https://paste.fo/", "https://paste.fo/raw/")
                output["links"].append(raw_link)
        return output

    async def __scrape_pastebin_pl(self, url: str, total_pages: int) -> dict:
        """
        Scrapes combo lists from pastebin.pl.

        Args:
            url (str): The base URL.
            total_pages (int): The total number of pages to scrape.

        Returns:
            dict: A dictionary containing titles and links of combo lists.
        """

        output = {"titles": [], "links": []}
        for page in range(total_pages):
            page_url = f"{url}{page}"
            print(f"[+] Fetching: {page_url}")
            response = await self.__get_source(page_url)
            css_identifier_result = ".first"
            css_identifier_link = "a"
            results = response.html.find(css_identifier_result)
            for result in results:
                details = result.find(css_identifier_link, first=True)
                if details:
                    output["titles"].append(details.text)
                    raw_link = details.absolute_links.pop().replace("https://pastebin.pl/view/",
                                                                    "https://pastebin.pl/view/raw/")
                    output["links"].append(raw_link)
        return output

    @staticmethod
    async def __clean_email_list(string_text: str) -> list[str]:
        """
        Cleans and validates email lists from a raw text.

        Args:
            string_text (str): The raw text containing email lists.

        Returns:
            list[str]: A cleaned and validated list of email:password combos.
        """

        # validate email
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        unwanted = string_text.split(" ")
        combo_list = []
        for text in unwanted:
            if ":" in text and match(email_pattern, text.split(":")[0]):
                combo = text.strip(" ")
                email = combo.split(":")[0]
                password = combo.split(":")[1]
                if len(email) > 4 and len(password) > 4:
                    combo_list.append(combo)
        return combo_list

    async def _get_combos_file(self, query: str) -> any([str, None]):
        """
        Fetches combo lists based on a given query.

        Args:
            query (str): The query to search for combo lists.

        Returns:
            any([str, None]): The path to the generated combo file or None if no combos are found.
        """

        google_query = f"{query} site:paste.fo/raw"
        print(f"[+] Fetching Google: {google_query}")
        google_links: list = await self.__scrape_google_links(query=google_query)

        total_accounts_list = []

        # Scrape additional links
        for additional_link in self.__additional_list_to_scrape:
            print(f"[+] Fetching {additional_link}")
            additional_links = await self.__scrape_paste_fo(url=additional_link)
            google_links.extend(await self.__filter_and_clean_links(additional_links, query))

        # Scrape pastebin.pl
        pastebin_links = await self.__scrape_pastebin_pl(url="https://pastebin.pl/lists/", total_pages=12)
        google_links.extend(await self.__filter_and_clean_links(pastebin_links, query))

        # Fetch and clean accounts from all links
        for link in google_links:
            source = await self.__get_source(url=link)
            raw_string = str(source.html.text)
            total_accounts_list.extend(await self.__clean_email_list(string_text=raw_string))

        if len(total_accounts_list) < 1:
            return None
        file_name: str = path.join(GlobalVariables.COMBO_PATH.value, 'combos.txt')
        with open(file=file_name, mode='w', encoding='utf-8') as combo_file:
            combo_file.write("\n".join(total_accounts_list))
        return file_name

    @staticmethod
    async def __filter_and_clean_links(links_data: dict, query: str) -> list[str]:
        """
        Filters and cleans combo list links.

        Args:
            links_data (dict): A dictionary containing titles and links of combo lists.
            query (str): The query to filter links.

        Returns:
            list[str]: A list of filtered combo list links.
        """

        filtered_links = []
        for index, title in enumerate(links_data["titles"]):
            if query.lower() in title.lower():
                filtered_links.append(links_data["links"][index])
        return filtered_links

    async def generate_combos(self, client: listen.Client, message: Message) -> None:
        """
        Initiates the combo list generation process.

        Args:
            client (listen.Client): The Pyrogram Client for handling communication.
            message (Message): The message object containing user input and context.

        Returns:
            None
        """

        if not EnableDisableFeatures.IS_GET_COMBO_COMMAND_AVAILABLE.value:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=EnableDisableFeatures.TEMP_BLOCK_MESSAGE.value,
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return

        try:
            target_query: any = await client.ask(
                message.chat.id,
                text='Please enter the name of the service (e.g., Netflix).',
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
        print(f"===============> GENERATING COMBOS-{target_query} <===============")

        await self._utils.send_text_message(client=client, message=message,
                                            text=f'Combos are being fetched for {target_query}. Please wait.')
        file_name = await self._get_combos_file(query=target_query)
        if not file_name:
            await self._utils.send_text_message(client=client, message=message,
                                                text='No combinations were found related to your search query.')
            return

        try:
            await self._utils.send_document_files(
                client=client,
                message=message,
                document_path=file_name,
                caption_text=GlobalVariables.BOT_STATICS_MESSAGE.value,
            )
        except ValueError as e:
            print(e)
            await self._utils.send_text_message(
                client=client,
                message=message,
                text="UNKNOWN ERROR: while sending file"
            )



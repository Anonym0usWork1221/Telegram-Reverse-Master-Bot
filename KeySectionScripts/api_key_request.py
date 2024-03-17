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
from KeySectionScripts.api_key_req_headers import HEADERS
from CommonSectionScripts.randomuser import users
import requests
import random
import json
import os


async def request_new_key(generated_key: str) -> str:
    url: str = ' https://ctxt.io/new'
    HEADERS["user-agent"] = random.choice(users)
    response: requests.Response = requests.post(url=url, data={"content": generated_key, "ttl": "1h"}, headers=HEADERS)
    if response.history and response.status_code == 200:
        key_url: str = response.url
    else:
        print("[-] Unable to gain link")
        return f"Key generation is unsuccessful due to an error. Please use it directly.\n```{generated_key}```"

    if EnableDisableFeatures.IS_SHORT_GENERATED_LINK:
        # shortening the url using an api key
        command_execution_result: str = os.popen(
            f'curl -H "public-api-token: {GlobalVariables.LINK_SHORTER_API_KEY}" -X PUT -d '
            f'"urlToShorten={key_url}" https://api.shorte.st/v1/data/url'
        ).read()
        if command_execution_result:
            json_response: dict = json.loads(s=command_execution_result)
            if json_response["status"].lower() == "ok":
                return json_response["shortenedUrl"]

    print(f"Key Url: {key_url}")
    return key_url

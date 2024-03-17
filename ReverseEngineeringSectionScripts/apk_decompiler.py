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

from global_variables import PreDefinedPipeCommands, GlobalVariables, EnableDisableFeatures
from os import path, makedirs, listdir
from pyrogram import Client, filters
from pyrogram.types import Message
from pyromod import helpers, listen
from Utils.utils import Utilities
from zipfile import ZipFile
import shutil


class ApkReverseEngineering(object):
    """
    This class needs JDK and JRE

    for windows:
        winget install -e --id Oracle.JDK.17
        winget install -e --id Oracle.JavaRuntimeEnvironment
    for linux based systems:
        sudo apt install default-jre -y
        sudo apt install default-jdk -y

    A class responsible for the reverse engineering of APK files.

    Attributes:
        _app (Client): The Pyrogram Client instance.
        _utils (Utilities): An instance of the Utilities class for various utility functions.

    Methods:
        __init__(self, app: Client): Initializes the ApkReverseEngineering instance.
        _grant_permissions(self) -> None: Grants necessary permissions for APK decompiling tools.
        _reverse_apk_file(self, downloaded_apk_path: str, file_name_without_ext: str,
                          update_message: Message) -> any([None, str]): Handles the reverse engineering process.
        decompile_apk_file(self, client: listen.Client, message: Message) -> None:
            Initiates the de-compilation process for APK files.
    """

    def __init__(self, app: Client):
        """
        Initializes the ApkReverseEngineering instance.

        Args:
            app (Client): The Pyrogram Client instance.
        """

        self._app: Client = app
        self._utils: Utilities = Utilities(app=self._app)

    async def _grant_permissions(self) -> None:
        """
        Grants necessary permissions for APK decompiling tools.

        Returns:
            None
        """

        if GlobalVariables.PLATFORM.value != "windows":
            await self._utils.run_pipe_commands(
                commands_list=PreDefinedPipeCommands.APK_DECOMPILING_TOOLS_PERMISSIONS.value
            )

    async def _reverse_apk_file(self, downloaded_apk_path: str,
                                file_name_without_ext: str,
                                update_message: Message) -> any([None, str]):
        """
        Handles the reverse engineering process of APK files.

        Args:
            downloaded_apk_path (str): The path to the downloaded APK file.
            file_name_without_ext (str): The name of the APK file without the extension.
            update_message (Message): The message object for updating the user on runtime.

        Returns:
            Union[None, str]: The path to the decompiled ZIP file or None if the process encounters an issue.
        """

        # Grant tools permission if tool on linux os
        runtime_updates: str = "**__--[RUNTIME UPDATES]--__**\n\n"
        await self._grant_permissions()

        # Declaring all the apk files distribution paths
        base_apk_temp_path: str = path.join(GlobalVariables.BASE_PATH.value, "temp_apk_decompiler_dir")
        apk_zip_path: str = path.join(base_apk_temp_path, f"{file_name_without_ext}.zip")
        apk_unzip_path: str = path.join(base_apk_temp_path, f"{file_name_without_ext}_unzipped")
        dex_apk_classes_path: str = path.join(apk_unzip_path, "classes.dex")
        jar_apk_files_path: str = path.join(base_apk_temp_path, f"{file_name_without_ext}.jar")
        jar_to_java_apk_files_path: str = path.join(base_apk_temp_path, f"{file_name_without_ext}_java", "src")
        other_decompiled_apk_files_path: str = path.join(base_apk_temp_path, f"{file_name_without_ext}_re")
        decompiled_apk_output_path: str = path.join(GlobalVariables.BASE_PATH.value, file_name_without_ext)

        # Check if paths available else make them first
        if path.exists(path=base_apk_temp_path):
            shutil.rmtree(path=base_apk_temp_path)

        if path.exists(decompiled_apk_output_path):
            shutil.rmtree(path=decompiled_apk_output_path)

        makedirs(name=other_decompiled_apk_files_path, exist_ok=True)
        makedirs(name=decompiled_apk_output_path, exist_ok=True)
        makedirs(name=jar_to_java_apk_files_path, exist_ok=True)
        makedirs(name=base_apk_temp_path, exist_ok=True)
        makedirs(name=apk_unzip_path, exist_ok=True)

        # copy the apk to temp folder and make its zip file
        shutil.copy2(src=downloaded_apk_path, dst=apk_zip_path)

        # Unzip the .zip file (apk)
        zip_file_reference: ZipFile = ZipFile(file=apk_zip_path)
        zip_file_reference.extractall(path=apk_unzip_path)
        zip_file_reference.close()

        # Check if the unzipped apk got .dex files else it is invalid apk file
        if not path.exists(path=dex_apk_classes_path):
            print("Invalid apk file does not able to decompile it.")
            return None

        # Creating .jar files from .dex classes
        print("Creating Jar files from Dex classes")
        await update_message.edit(text=f"{runtime_updates}-> Reversing DEX classes.")
        if await self._utils.run_subprocess_command(
            command=f"{GlobalVariables.DEX_TO_JAR_PATH.value} {dex_apk_classes_path} -o {jar_apk_files_path}"
        ):
            runtime_updates += "-> **Completely reversed DEX classes**\n"
        else:
            runtime_updates += "-> **Partially reversed DEX classes**\n"

        print("Creating Java files from Jar files")
        await update_message.edit(text=f"{runtime_updates}-> Reversing Java source code (This may take a while).")
        # Reversing .jar file to java source code
        if await self._utils.run_subprocess_command(
            command=f"{GlobalVariables.JD_CLI_PATH.value} {jar_apk_files_path} -od {jar_to_java_apk_files_path}"
        ):
            runtime_updates += "-> **Completely reversed Java source code.**\n"
        else:
            runtime_updates += "-> **Partially reversed Java source code.**\n"

        print("Decompiling remaining files")
        await update_message.edit(text=f"{runtime_updates}-> Reversing remaining files (This may take a while).")
        # decompiling remaining files using apktool reverse engineering tool
        if await self._utils.run_subprocess_command(
            command=f"{GlobalVariables.APK_TOOL_PATH.value} d {downloaded_apk_path} "
                    f"-o {other_decompiled_apk_files_path} -f"  # using -f to override it
        ):
            runtime_updates += "-> **Completely reversed remaining files.**\n"
        else:
            runtime_updates += "-> **Partially reversed remaining files.**\n"

        print("Merging all files")
        await update_message.edit(text=f"{runtime_updates}-> Merging files.")
        # rearranging reversed file and folders to make a zip file from them
        others_decompiled_files_list: any = listdir(path=other_decompiled_apk_files_path)
        # moving the apktool decompiled files to destination folder
        for file in others_decompiled_files_list:
            shutil.move(src=path.join(other_decompiled_apk_files_path, file), dst=decompiled_apk_output_path)

        # moving java source files to destination folder
        shutil.move(src=jar_to_java_apk_files_path, dst=decompiled_apk_output_path)

        # Removing the temporary files to free up disk space
        if path.exists(path=base_apk_temp_path):
            shutil.rmtree(path=base_apk_temp_path)

        # making the zip file of output directory
        shutil.make_archive(
            base_name=f"{file_name_without_ext}_decompiled",
            format="zip",
            base_dir=path.basename(decompiled_apk_output_path),  # only provide the name of folder from current folder
        )

        # Clean the output folder to free up space
        if path.exists(decompiled_apk_output_path):
            shutil.rmtree(decompiled_apk_output_path)

        await update_message.edit(text=f"{runtime_updates}-> **Completely Merged files.**")
        # return the path to decompiled zip file
        return path.join(GlobalVariables.BASE_PATH.value, f"{file_name_without_ext}_decompiled.zip")

    async def decompile_apk_file(self, client: listen.Client, message: Message) -> None:
        """
        Initiates the de-compilation process for APK files.

        Args:
            client (listen.Client): The Pyrogram Client for handling communication.
            message (Message): The message object containing user input and context.

        Returns:
            None
        """

        if not EnableDisableFeatures.IS_DECOMPILE_APK_COMMAND_AVAILABLE.value:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text=EnableDisableFeatures.TEMP_BLOCK_MESSAGE.value,
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value),
                                                )
            return

        # remove old files to free up space
        await self._utils.run_pipe_commands(commands_list=PreDefinedPipeCommands.REMOVE_APKS.value)
        file: any([None, tuple[str, str, str, str, any]]) = await self._utils.preprocess_file(
            client=client,
            message=message,
            caption='Select a valid .apk file.',
            reply_markup=helpers.ikb(
                GlobalVariables.HELP_KEYBOARD_MENU.value),
            download_directory=GlobalVariables.APK_PATH.value,
            filters=(filters.document & filters.private),
            timeout=180
        )
        if not file:
            return
        new_name_with_path, old_name_with_path, file_name_without_ext, file_name_with_ext, user_file = file

        print(f"===============> DECOMPILING APK-{file_name_with_ext} <===============")

        await self._utils.send_text_message(client=client,
                                            message=message,
                                            text="The de-compilation process for the APK file has commenced. Kindly "
                                                 "take a moment to enjoy a cup of coffee while we manage the "
                                                 "operation. We anticipate completion within 4-5 minutes. Thank you "
                                                 "for your patience")
        update_message: Message = await self._utils.send_text_message(client=client,
                                                                      message=user_file,
                                                                      text="The message will update you in runtime")

        zip_file: any([None, str]) = await self._reverse_apk_file(
            downloaded_apk_path=new_name_with_path, file_name_without_ext=file_name_without_ext,
            update_message=update_message
        )
        if not zip_file:
            await self._utils.send_text_message(client=client,
                                                message=message,
                                                text="We encountered an issue while attempting to decompile the APK "
                                                     "file. This could be due to either an invalid APK archive or a "
                                                     "problem with our decompilation process. Please reach out to our "
                                                     "developers for further assistance and details",
                                                reply_markup=helpers.ikb(GlobalVariables.HELP_KEYBOARD_MENU.value)
                                                )
            return

        await self._utils.send_document_files(
            client=client, message=user_file, document_path=zip_file,
            caption_text=GlobalVariables.BOT_STATICS_MESSAGE.value
        )

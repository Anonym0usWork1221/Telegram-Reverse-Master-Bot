echo "Updating System"
sudo apt update -y && sudo apt upgrade -y

echo "Installing Python Virtual environment"
sudo apt install python3-venv -y

echo "Creating python venv"
python3 -m venv .venv

echo "Installing FFMPEG"
sudo apt install ffmpeg -y

echo "Installing python3 pip"
sudo apt install python3-pip -y

echo "Activating python venv"
source .venv/bin/activate

echo "Installing Python Requirements"
python3 -m pip install -r requirements.txt

echo "Installing Radar 2"
git clone https://github.com/radareorg/radare2
sudo chmod 777 radare2/sys/install.sh
radare2/sys/install.sh

echo "Installing Radar 2 extension r2dec"
sudo apt install meson ninja-build -y
r2pm -ci r2dec

echo "Installing JRE and JDK"
sudo apt install default-jre -y
sudo apt install default-jdk -y

clear
echo "Script is ready to be executed. type python3 main.py"


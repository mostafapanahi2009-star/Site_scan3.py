pkg update && pkg upgrade -y
pkg install python -y
pkg install git -y
pip3 install --upgrade pip
pip3 install requests rich
pkg install curl wget -y
python3 site_scan2.py

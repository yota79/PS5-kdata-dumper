HOWTO:

To compile you need the ps5-payload-dev/sdk ( you can find here https://github.com/yota79/sdk.git)
After download and set sdk clone this repo and from the folder do make
Inject the elf created with the command:
set PS5 ip : PS5IP=192.168.X.X
execute: socat -t 99999999 - TCP:$PS5IP:9021 < dump_kdata.elf
This create inside the PS5 inside /data the file dump of your kernel

To extract some information from your dump you have to do:
ROPgadget --binary kdump_fw_70101.bin --rawArch x86 --rawMode 64 --rawEndian little --all --depth 15 > ropgadget_exhaustive.txt
and after use the find_offset.py as:
python find_offset.py ropgadget_exhaustive.txt

@echo off
setlocal enabledelayedexpansion
net start msmq
set process_name=mqsvc.exe
set pid=
rd /s /q out
for /f "tokens=2 delims=," %%a in ('tasklist /nh /fi "imagename eq %process_name%" /fo csv') do (
    set pid=%%~a
    goto end
)

:end
if defined pid (
    afl-fuzz.exe -A %pid% -i in -o out -y -t 200 -l custom_net_fuzzer.dll -- -instrument_module mqqm.dll -target_module mqqm.dll -target_offset 0x51c94 -nargs 1 -patch_return_addresses -iterations 50000 -persist -- test_gdiplus.exe @@
) else (
    echo Process %process_name% not found
)


#!/bin/bash

# Pobierz od użytkownika dane wejściowe
read -p "Podaj pierwszy dzień zbierania danych (X): " X
read -p "Podaj drugi dzień zbierania danych (Y): " Y

# Pobierz aktualny miesiąc

# Madrid 172.233.96.42
REMOTE_HOST=172.233.96.42
MONTH=$(date +%m)
REMOTE_PATH=/root/wut_thesis/wut_thesis_honey/results

# Ustaw nazwę katalogu lokalnego
LOCAL_DIR="."



# Ścieżki docelowe w lokalnym katalogu
LOCAL_FILE1="${LOCAL_DIR}/shell_line_${X}-${Y}_${MONTH}_24.log"
LOCAL_FILE2="${LOCAL_DIR}/remote_exec_${X}-${Y}_${MONTH}_24.log"

# Pobranie plików przez SCP
echo "Pobieranie plików zdalnych..."
scp -P 2222 root@"${REMOTE_HOST}:${REMOTE_PATH}/shell_line_${X}-${Y}_${MONTH}_24.log" "$LOCAL_FILE1"
if [ $? -eq 0 ]; then
    echo "Pobrano shell line log jako $LOCAL_FILE1"
else
    echo "Błąd podczas pobierania shell_line.log"
fi

scp -P 2222 root@"${REMOTE_HOST}:${REMOTE_PATH}/remote_exec_${X}-${Y}_${MONTH}_24.log" "$LOCAL_FILE2"
if [ $? -eq 0 ]; then
    echo "Pobrano remote_exec.log jako $LOCAL_FILE2"
else
    echo "Błąd podczas pobierania remote_exec.log"
fi

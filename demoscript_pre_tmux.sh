#!/bin/bash

echo "$#"

if [[ $# -ne 0 ]]
then
	echo "Running in interactive mode"
else
	echo "Running in non-interactive mode"
fi


# VIDEO
Video_plain=demoData/images/sample-video-2.mp4
Video_encrypted=demoData/images/video_encrypted
Video_decrypted=demoData/images/video_decrypted

producer_key_file=demoData/keys/producer_aes_key.txt
consumer_0_key_file=demoData/keys/consumer_aes_key_0.txt
consumer_1_key_file=demoData/keys/consumer_aes_key_1.txt

display_offset_0="480x260+5%+14%"   # Will need to be adjusted for target resolution
display_offset_1="480x260+13%+36%"  # Maybe switching to %-based targets to make portable

# Assistant functions
error_highlight()(set -o pipefail;"$@" 2> >(sed $'s,.*,\e[31m&\e[m,'>&2) || (printf "\n\e[31mAES DECRYPTION FAILURE\e[m\n";\
  zenity --error --text="AES Decryption Failure" --title="Process Failure" --width=200 --height=80 2>/dev/null &))

# Prep tmux
tmux set pane-border-status top
tmux select-pane -T 'Main'

#display plaintext video
mpv --geometry="$display_offset_0" --loop $Video_plain --really-quiet & printf "Playing original video\n" & PIDp=$(pgrep -af "mpv" | awk '{print $1}') # This sends mpv render to subproc as side effect

#randomize key generation
KEY_ENCRYPT=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)

if [[ $# -eq 0 ]]; then sleep 2; else read -p "Hit any key>" ; printf "\n"; fi

#encrypt video with the key generated
error_highlight openssl aes-256-cbc -e -md SHA256 -in $Video_plain -out $Video_encrypted -K "$KEY_ENCRYPT" -iv "$IV"

#write key to a file that will be read by the pre-producer
echo "$KEY_ENCRYPT" > $producer_key_file

if [[ $# -eq 0 ]]; then sleep 5; else read -p "Hit any key>" ; printf "\n"; fi

#run the palisade pre-server
tmux split-window -h
printf "Starting server\n"
tmux send 'build/bin/pre_server_demo -p 12345' ENTER

if [[ $# -eq 0 ]]; then sleep 5; else read -p "Hit any key>" ; printf "\n"; fi

#run the palisade pre-producer
tmux select-pane -t 0
tmux split-window -h
tmux select-layout even-horizontal  # Even horizontally here to get horizontal even tiles
printf "Starting producer\n"
tmux send 'build/bin/pre_producer_demo -n producer -i localhost -p 12345' ENTER
printf "Producer completed\n"
tmux select-pane -t 2
tmux select-pane -T 'Server'

# Reorganize panes
tmux select-pane -t 0
tmux split-window -v
tmux select-pane -t 1
tmux swap-pane -s 1 -t 0
tmux select-pane -t 0 -T "Display Area"
tmux select-pane -t 1 -T "Main"

if [[ $# -eq 0 ]]; then sleep 5; else read -p "Hit any key>" ; printf "\n"; fi

tmux select-pane -t 2
tmux select-pane -T 'Producer'
tmux split-window -v
#run the palisade pre-consumer
printf "Starting consumer 1\n"
tmux send 'build/bin/pre_consumer_demo -n consumer_1 -d 0 -i localhost -p 12345' ENTER
printf "Consumer 1 completed\n"
tmux select-pane -t 3
tmux select-pane -T 'Consumer 1(valid key)'

# Create final pane for later
tmux select-pane -t 4
tmux split-window -v
tmux select-pane -t 5
tmux select-pane -T 'Consumer 2(invalid key)'

if [[ $# -eq 0 ]]; then sleep 15; else read -p "Hit any key>" ; printf "\n"; fi

tmux select-pane -t 1
#read key from file written by pre-consumer
KEY_DECRYPT=$(cat $consumer_0_key_file)

printf "AES Decrypt Video Consumer 1\n"

error_highlight openssl aes-256-cbc -d -md SHA256 -in $Video_encrypted -out $Video_decrypted -K "$KEY_DECRYPT" -iv "$IV"

if [[ $# -eq 0 ]]; then sleep 1; else read -p "Hit any key>" ; printf "\n"; fi

#display decrypted video
mpv --geometry=$display_offset_1 --loop $Video_decrypted --really-quiet & printf "Playing decrypted video\n"  # This sends mpv render to subproc as side effect

if [[ $# -eq 0 ]]; then sleep 10; else read -p "Hit any key>" ; printf "\n"; fi

#######################33
tmux select-pane -t 5
#run the palisade pre-consumer without access
printf "Starting consumer 2\n"
tmux send 'build/bin/pre_consumer_demo -n consumer_2 -d 1 -i localhost -p 12345' ENTER
printf "Consumer 2 completed\n"

if [[ $# -eq 0 ]]; then sleep 17; else read -p "Hit any key>" ; printf "\n"; fi

tmux select-pane -t 1
#read key from file written by pre-consumer
KEY_DECRYPT=$(cat $consumer_1_key_file 2>/dev/null)

printf "AES Decrypt Video Consumer 2\n\n"

error_highlight openssl aes-256-cbc -d -md SHA256 -in $Video_encrypted -out $Video_decrypted -K "$KEY_DECRYPT" -iv "$IV"

# To allow for the message box to appear unrelated to the closing of the videos
if [[ $# -eq 0 ]]; then sleep 5; else read -p "Hit any key>" ; printf "\n"; fi

read -p "Hit any key to close windows and shut down the PRE demo>"

#close opened videos
kill -9 "$PIDp"
PIDd="$(pgrep -af "mpv" | awk '{print $1}')"
for p in $PIDd
do
	kill -9 $p > /dev/null
done


#shutdown server
PIDs="$(pgrep -af "pre_server_demo" | awk '{print $1}')"
kill -9 "$PIDs"

#shutdown tmux
tmux kill-server

#remove generated keys
rm $producer_key_file $consumer_0_key_file $consumer_1_key_file
rm $Video_encrypted $Video_decrypted

#put terminal back into a good state. 
reset

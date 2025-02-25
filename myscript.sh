
if [ $# -eq 0 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi


file_name="$1"


touch "$file_name"


locked_file="${file_name}.locked"
touch "$locked_file"



echo "Some data" > "$locked_file"


rm "$file_name"



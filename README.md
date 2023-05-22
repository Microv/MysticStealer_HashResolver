# MysticStealer HashResolver
IDA Python Script to resolve APIs in Mystic Stealer samples

Tested on sample `SHA256: 7c185697d3d3a544ca0cef987c27e46b20997c7ef69959c720a8d2e8a03cd5dc`

## Prerequisites
- Offset of the function used to resolve the APIs (in the analyzed sample `sub_00E3AD59` with Base address 0xE20000)
- Must run on Windows to have access to the list of DLLs in the System32 directory

## Usage
- Set the value of the variable `r_offset` to the offset of the function used to resolve the APIs in the analyzed sample 
- Run the script in IDA Pro

## HOW TO RUN:

1) Have python installed
2) Run "aes.py" using "python ./aes.py {Key Size} {Encrypt Or Decrypt} {EBC or CBC}".
    Where Key Size = 128, 192, 256
          Encrypt or Decrypt = enc or dec
          EBC or CBC = ebc or cbc

    Example: python ./aes.py 128 enc ebc

## STEPS OF AES:

1) Read Plaintext into blocks of 128 each
2) Read key and expand it (using Key Exapnsion algorithm).
3) Add round 0 and then do the entire AES process (Sub bytes, Shift row, Mix Column, Add round key)
4) Apply encryption/decryption in EBC/CBC mode for the given PT and Key
5) Write the results to respective files

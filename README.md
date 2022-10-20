## HOW TO RUN:

1) Python must be installed
2) Run "aes.py" using "python ./aes.py {Key Size} {Encrypt Or Decrypt} {ECB or CBC}"
   Where:
  
    - Key Size = 128, 192, 256

    - Encrypt or Decrypt = enc or dec

    - EBC or CBC = ecb or cbc

    Example: `python ./aes.py 128 enc ecb`

## Input:

1) Plaintext should be in **pt.pt** file
2) Key should be in **key.key** file
3) Initialization vector should be in **IV.txt** file (Used only for CBC mode)

## Output:

1) Ciphertext will be in **encrypted.enc** file
2) Decrypted plaintext will be in **decrypted.dec** file

All Input and Output files are in **Hex** format.

## STEPS OF AES:

### Encryption:
1) Read Plaintext into blocks of 128 each
2) Read key and expand it to use in each round of AES (using Key Exapnsion algorithm)
3) Add Round 0 key with Plaintext and then do the entire AES process (Sub Bytes, Shift Row, Mix Column, Add round key) for each round
4) Mix Column is not done in the last round
5) Repeat the same process for each block of plaintext

### Decryption:
1) Decryption is the same as encryption but in reverse order

## Throughput:

- The throughput calculated for the encryption process is: 4096 Bytes/Sec on average.
- The throughput calculated for the decryption process is: 4096 Bytes/Sec on average.

## Extra Credit:

1) Implemented AES in CBC mode
2) Implemented AES in ECB mode
3) Implemented AES in 128, 192, 256 bit key sizes

## Collaborators:

1) Hamza Iftikhar - 19I-2003
2) Hamza Nasir &nbsp;&nbsp;&nbsp;- 19I-0700
3) Abdullah Nasir - 19I-0527


## References:
[AES FIPS 197](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwiZws_X2ev6AhUMiGMGHdPzC0IQFnoECBYQAQ&url=https%3A%2F%2Fnvlpubs.nist.gov%2Fnistpubs%2Ffips%2Fnist.fips.197.pdf&usg=AOvVaw0J97nT9qC7WdbmybdjrXHE)

## HOW TO RUN:

1) Have python installed
2) Run "aes.py" using "python ./aes.py {Key Size} {Encrypt Or Decrypt} {EBC or CBC}".
   Where:
  
    - Key Size = 128, 192, 256

    - Encrypt or Decrypt = enc or dec

    - EBC or CBC = ebc or cbc

    Example: `python ./aes.py 128 enc ebc`

## STEPS OF AES:

1) Read Plaintext into blocks of 128 each
2) Read key and expand it to use in each round of AES (using Key Exapnsion algorithm)
3) Add Round 0 key with Plaintext and then do the entire AES process (Sub Bytes, Shift Row, Mix Column, Add round key) for each round
4) Apply encryption/decryption using encyption/decryption Flag
5) Write the results to respective files (.enc for encryption and .dec for decryption)

## Throughput:
1) The throughput calculated for the encryption process is: 3979.162 bytes/sec on average.
2) The throughput calculated for the decryption process is: 6272.73 bytes/sec on average.

## Extra Credit:

1) Implemented AES in CBC mode
2) Implemented AES in EBC mode
3) Implemented AES in 128, 192, 256 bit key sizes

## Collaborators:

1) Hamza Iftikhar - 19I-2003
2) Hamza Nasir &nbsp;&nbsp;&nbsp;- 19I-0700
3) Abdullah Nasir - 19I-0527


## References:
[AES FIPS 197 for Key Expansion Algorithm](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwiZws_X2ev6AhUMiGMGHdPzC0IQFnoECBYQAQ&url=https%3A%2F%2Fnvlpubs.nist.gov%2Fnistpubs%2Ffips%2Fnist.fips.197.pdf&usg=AOvVaw0J97nT9qC7WdbmybdjrXHE)

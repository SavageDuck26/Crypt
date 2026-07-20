Crypt is made for storing large amounts of data privately. Think of it like putting your data in a coffin that only you know where you buried.

Files and Folders input into Crypt will be compressed with Zstd at the maximum level, then encrypted with AES-GCM256. 

Encryption keys are derived using Argon2 on heavy settings, with extra large salt additions.

Crypt by default uses one worker, and a .json will be created when it is first run. You can change the amount of workers in the .json to increase the speed of encryption. 
It's recommeneded to use 2-4 less workers than CPU cores your computer has. Each worker takes around 800mb of RAM, which I will be working to lower.

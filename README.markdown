## EGCDAsyncSocket
This is a fork from Robbie Hanson's CocoaAsyncSocket, which has made my life easier. 
Since it's helped me out so much, I wanted to add the ability to do non SSL encryption (AES256) with another host that supports it.

<h3>What</h3>
- **AES256 symmetric encryption**<br/>
  SSL relies on a private key, but when there's no centralized server, how do you encrypt communication between devices?<br/>
  An ad-hoc approach let's us generate the same key on both devices using a passcode. <br/>
  To make things easier, encryption and decryption will all be done inside EGCDAsyncSocket. 
- **Key Derivation**<br/>
  I'll  be adding in the--industry approved/Apple implemented--key derivation function PBKDF2 (Password-Based Key Derivation Function 2). 
  This will allow a programmer to create a secure crypto key that can then be used with this updated class.

<h3>Why</h3>
- I had need for a pure symmetric encryption implementation. 
- The distributed approach (no centralized server) meant that I couldn't bake in a private key; if I did, a hacker could do a hex dump of the program and extract the private key very easily, comprimising 100% of program-program communications.
- Most often, I see programmers in stackoverflow threads using C strings as an encryption key which is extremely weak and insecure.
Hopefully this integrated key generation will mean more and better communications security in the programming community.



For GCDAsyncSocket related questions, wiki, and issues, please go to https://github.com/robbiehanson/CocoaAsyncSocket 

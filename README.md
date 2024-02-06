# feistel-py
_Feistel cipher implementation in Python for format-preserving encryption_


![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/cyrildever/feistel-py)
![GitHub last commit](https://img.shields.io/github/last-commit/cyrildever/feistel-py)
![GitHub issues](https://img.shields.io/github/issues/cyrildever/feistel-py)
![GitHub license](https://img.shields.io/github/license/cyrildever/feistel-py)

This is a Python library implementing the Feistel cipher for Format-Preserving Encryption (FPE).

### Motivation

The main objective of this library is not to provide a secure encryption scheme but rather a safe obfuscation tool.


### Formal description

This library operates on the concept of the Feistel cipher described in [Wikipedia](https://en.wikipedia.org/wiki/Feistel_cipher) as:
> A Feistel network is subdivided into several rounds or steps. In its balanced version, the network processes the data in two parts of identical size. On each round, the two blocks are exchanged, then one of the blocks is combined with a transformed version of the other block.
> Half of the data is encoded with the key, then the result of this operation is added using an XOR operation to the other half of the data.
> Then in the next round, we reverse: it is the turn of the last half to be encrypted and then to be xored to the first half, except that we use the data previously encrypted.
> The diagram below shows the data flow (the ![${\oplus}$](https://render.githubusercontent.com/render/math?math={\oplus}) represents the XOR operation). Each round uses an intermediate key, usually taken from the main key via a generation called key schedule. The operations performed during encryption with these intermediate keys are specific to each algorithm.

![](assets/400px-Feistel_cipher_diagram_en.svg.png)

The algorithmic description (provided by Wikipedia) of the encryption is as follows:
* Let ![$n+1$](https://render.githubusercontent.com/render/math?math=n%2B1) be the number of steps, ![$K_{0},K_{1},...,K_{n}$](https://render.githubusercontent.com/render/math?math=K_{0},K_{1},...,K_{n}) the keys associated with each step and ![$F:\Omega\times\mathcal{K}\mapsto\Omega$](https://render.githubusercontent.com/render/math?math=F:\Omega{\times}K\mapsto\Omega) a function of the ![$(words{\times}keys)$](https://render.githubusercontent.com/render/math?math=(words{\times}keys)) space to the ![$words$](https://render.githubusercontent.com/render/math?math=words) space.
* For each step ![$i{\in}[0;n]$](https://render.githubusercontent.com/render/math?math=i\in[0%3Bn]), note the encrypted word in step ![$i,m_{i}=L_{i}||R_{i}$](https://render.githubusercontent.com/render/math?math=i,m_{i}=L_{i}||R_{i}):
  * ![$L_{i+1}=R_{i}$](https://render.githubusercontent.com/render/math?math=L_{i%2B1}=R_{i})
  * ![$R_{i+1}=L_{i}{\oplus}F(L_{i},K_{i})$](https://render.githubusercontent.com/render/math?math=R_{i%2B1}=L_{i}{\oplus}F(L_{i},K_{i}))
* ![$m_{0}=L_{0}||R_{0}$](https://render.githubusercontent.com/render/math?math=m_{0}=L_{0}||R_{0}) is the unciphered text, ![$m_{n+1}=L_{n+1}||R_{n+1}$](https://render.githubusercontent.com/render/math?math=m_{n%2B1}=L_{n%2B1}||R_{n%2B1}) is the ciphered word. 

There is no restriction on the ![$F$](https://render.githubusercontent.com/render/math?math=F) function other than the XOR operation must be possible. For simplicity, we will choose ![$L_1$](https://render.githubusercontent.com/render/math?math=L_1) of the same size as ![$R_1$](https://render.githubusercontent.com/render/math?math=R_1) and the function ![$F$](https://render.githubusercontent.com/render/math?math=F) shall transform a word of length ![$k$](https://render.githubusercontent.com/render/math?math=k) into a word of length ![$k$](https://render.githubusercontent.com/render/math?math=k) (and this for all ![$k$](https://render.githubusercontent.com/render/math?math=k)).


### Usage

```
pip install feistel-py
```

To get an obfuscated string from a source data using the SHA-256 hashing function at each round, first instantiate a `Cipher` object, passing it a key and a number of rounds. Then, use the `encrypt()` method with the source data as argument. The result will be a byte array. To ensure maximum security, I recommend you use a 256-bit key or longer and a minimum of 10 rounds.

The decryption process uses the obfuscated buffered data and pass it to the `decrypt()` method of the `Cipher`.

```python
from feistel.cipher import Cipher


source = "my-source-data"

# Encrypt
cipher = Cipher("some-32-byte-long-key-to-be-safe", 10)
obfuscated = cipher.encrypt(source)

# Decrypt
deciphered = cipher.decrypt(obfuscated)

assert deciphered == source, "deciphered should be 'my-source-data'"
```
_NB: This is the exact replica of my other implementations (see below)._

You may also use your own set of keys through a `CustomCipher` instance, eg.
```python
from feistel.custom import CustomCipher


keys = [
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
]
cipher = CustomCipher(keys)
```
In that case, the number of rounds depends on the number of provided keys.

Finally, you might want to use the latest cipher, providing true format-preserving encryption for strings:
```python
from feistel.fpe import FPECipher
from feistel.utils.hash import SHA_256


cipher = FPECipher(SHA_256, "some-32-byte-long-key-to-be-safe", 128)
obfuscated = cipher.encrypt(source)

assert len(obfuscated) == len(source)
```
_NB: For stability and security purposes, the number `0` always returns itself._


You might also want to use it with the command line:
```
usage: python3 -m feistel [-h] [-c CIPHER] [-e ENGINE] [-k KEY] [-r ROUNDS] [-o OPERATION] input

positional arguments:
  input                 The string to obfuscate (watch for quotes)

options:
  -h, --help            show this help message and exit
  -c CIPHER, --cipher CIPHER
                        The type of cipher: feistel [default] | custom | fpe
  -e ENGINE, --engine ENGINE
                        The hashing engine [default sha-256]
  -k KEY, --key KEY     The key(s) to use
  -r ROUNDS, --rounds ROUNDS
                        The (optional) number of rounds [default 10]
  -o OPERATION, --operation OPERATION
                        The operation to process : cipher | decipher
```


### Dependencies

The following libraries are necessary:
- `pycryptodome`;
- `py-utls`.


### Tests

```console
$ python3 -m unittest discover
```


### Other implementations

For those interested, I also made two other implementations of these ciphers:
* In [Golang](https://github.com/cyrildever/feistel) as an executable;
* In [Typescript](https://github.com/cyrildever/feistel-cipher) for the browser;
* In [Scala](https://github.com/cyrildever/feistel-jar) for the JVM.

I also created a special library for redacting classified documents using the new FPE cipher. Feel free to [contact me](mailto:cdever@edgewhere.fr) about it.


### License

This module is distributed under a MIT license. \
See the [LICENSE](LICENSE) file.


<hr />
&copy; 2024 Cyril Dever. All rights reserved.
# JWBinder 
JWBinder is derived from JStap (Aurore Fass) and MinerRay (Alan Romano). 
Cite their awesome works if this project helps you.

## Environment

You need to install node and python3.

```
cd src/Parser && node -i
```
## How to use it?

### Reconstruct JWMM to shadow JavaScript:
```
cd src
# You should configure the rootdir of JWMMs in SAT.py
Python3 hooker/SAT.py
# Then you could use the JS detector for handling JWMMs!
```
### Parse the WASM to JS-format AST:

```
cd src/Parser
# You should configure the input WASM path by modifying FILE_TO_READ and FILE_TO_WRITE in parser_new.js
node parser_new.js
```

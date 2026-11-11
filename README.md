# AES_Attestation_Filter_Reduction
Companion GitHub codebase for M. Boese senior honor's thesis paper: "Implementing Linguistic Attestation as a Filter for Reducing AES Probability Space"

Main test algorithm runs from Decryption.py. Decryption.py accesses code from AES.py and KeyFill.py at the same directory level.

Decryption.py requires reference to a csv of data attestation boolean values in sys arg 1 position. 
The provided companion folder contains the files used for this purpose, as well as the code used to process Wikimedia text files into the csvs.

All code was completed in Python and run using the UF Hiper Gator supercomputer for the research.

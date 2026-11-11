# AES_Attestation_Filter_Reduction
Companion GitHub codebase for M. Boese senior honor's thesis paper: "Implementing Linguistic Attestation as a Filter for Reducing AES Probability Space"

Main test algorithm runs from Decryption.py. Decryption.py accesses code from AES.py and KeyFill.py at the same directory level.

Decryption.py requires reference to a csv of data attestation boolean values in sys arg 1 position. 
The provided companion folder contains the code "GatherAttestation.py" which was used to extract data from Wikimedia bz2 dumps.
Wikimedia dumps are provided through "https://dumps.wikimedia.org/other/mediawiki_content_current/" under CC Share Alike 4.0.


(Citation:: Wikimedia Foundation. (2026). English Wikipedia database dump [Data set]. Wikimedia Downloads. [https://dumps.wikimedia.org/enwiki/
](https://dumps.wikimedia.org/other/mediawiki_content_current/enwiki/), 
Wikimedia Foundation. (2026). Chinese Wikipedia database dump [Data set]. Wikimedia Downloads. [https://dumps.wikimedia.org/zhwiki/
](https://dumps.wikimedia.org/other/mediawiki_content_current/zhwiki/) )

All code was completed in Python and run using the UF Hiper Gator supercomputer for the research.

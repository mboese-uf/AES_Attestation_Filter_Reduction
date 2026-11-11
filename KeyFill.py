#Get all keys from doing key expansion in reverse

#Imports
#Galois citation: 
# Hostetter, M. (2020). Galois: A performant NumPy extension for Galois fields [Computer software]. https://github.com/mhostetter/galois
import galois
import math
import numpy as np
import AES
import csv
from tqdm import tqdm
#=====================================================


#Create the finite field for conducting operations in
#The irreducible polynomial from Section 4.2 is explicitly defined
#Hexadecimal of the irreducible polynomial is 11B
GF = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")

#Inverse rotate word method
#The same as AES.rotWord, but moves indices to the right instead of left
def invRotWord(word):
    #Create a new word to move bytes to
    wordP = np.empty(4, dtype=int)
    #Move the byte at index 3 to index 0
    wordP[0] = word[3]
    #Go through each other byte and move it to a new spot
    for i in range(3):
        wordP[i+1] = word[i]
    #Return the rotated word
    return wordP
#=====================================================

#Inverse sub word method
#The same as AES.subWord, but uses the substitiution box from AES.invSubBytes
def invSubWord(word):
    #Defining the constant SBox (substitution table)
    #Values taken from NIST AES Section 5.1.1 Table 4. SBOX() substitution values
    #This is written in hexadecimal but the type is set to ints for use with the galois library
    invSBox = np.array([
        [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
        [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
        [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
        [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
        [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
        [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
        [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
        [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
        [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
        [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
        [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
        [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
        [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
        [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
        [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]], dtype=int)
        
        #Go through every byte in the word
    for i in range(4):
        #Get the byte from the index
        byte = int(word[i])
        #Get the y value for the sBox
        sBoxY = math.floor(byte/16)
        #Get the x value for the sBox
        sBoxX = byte%16
        #Replace the byte with the new byte from the sBox
        word[i] = invSBox[sBoxX, sBoxY]
    #Return the now substituted word
    return word
#=====================================================

#Prior word method
#Fills the last word based on the current word (i) and the i+nk-1 word based on key expansion formulas
#Will be used for an iterative reverse fill
#Requires the current index (i), an array of all words (words), and nk 
#For AES256 (target AES) nk=8
def priorWord(i, words, nk):
    #Initialize a value for use of the table j[i] with all 0s. 
    #j[0] will be set to the correct value upon being called
    #j[i] is explained in Table 5 of section 5.2
    j = GF(np.array([0, 0, 0, 0],  dtype=int))

    words = GF(words)

    #Get current word and the word after it
    current = GF(words[i-1]).copy()
    future = GF(words[i]).copy()

    #Using the key expansion method's math - in GF 2^8 x+y=z and z+y=x because + is equivalent to XOR
    #First, apply any transformations that may have occured to the current word during key expansion
    #If nk%ti is 0...
    if i%nk==0:
        #... Rotate the word, sub it, and add j
        j[0] = int(2**(i/nk))
        current = np.add(GF(AES.subWord(AES.rotWord(current))), j)

    #Otherwise, if Nk is bigger than 6 and i mod Nk is 4...
    elif (nk > 6) and (i%nk==4):
        #...Apply subWord to the current word
        current = GF((AES.subWord(current)))

    #Add the transformed current word with the future word to get the target word
    newWord = GF(np.add(current, future))

    words[(i-nk)] = newWord
    return words
#=====================================================

#Reverse fill method
#Fills an entire key from the last nk words (nk=8 and nr=14 in AES256)
#nr is 
def reverseFill(keyEnd, nr=14, nk=8):
    #Make an empty expanded key to fill the entire key from, where the last x words are keyEnd (use vstack to append it to the end)
    expKey = GF(np.full(((4*nr+4)-nk, 4), [0, 0, 0, 0]))
    expKey = GF(np.vstack((expKey, keyEnd)))
    #Go from the end of the entire key
    for i in range(len(expKey)-nk):
        #Get the target index when going in reverse order (ri for reverse index)
        ri = len(expKey) - (1 + i)
        #Use prior word to fill the next word
        expKey = priorWord(ri, expKey, nk)

    #After filling all words, return the key
    return expKey
#=====================================================

#Sequential fill method
#Fills the key from a start key a number of specified runs
#Mostly accounts for word boundary issues
def seqFill(number, startkey):
    #Current key applies GF (also better readability)
    key = startkey
    #Make an array to hold all keys
    #Format will be tuples: (last 8 words, full key)
    keyArray = []
    #Go through the procedure a number of times equal to number
    for i in tqdm(range(number)):
        fullKey = reverseFill(key)
        keyArray.append((key, fullKey))

        #Increase the key by one
        key = increaseKeyOne(key)

    #At the end, return the keyArray
    return keyArray
#=====================================================

#Increase key
def increaseKeyOne(key):
    #Check if adding one to the key will put it over the word/byte boundary
    word = -1
    byte = -1
    #Using a try loop in case a key becomes larger than possible
    try:
        while key[word][byte] == 255:
            #If we are at the end of the word, reset byte to -1
            #Subtract 1 from word (this is moving to the next word because the word is [255, 255, 255, 255])
            if byte == -4:
                byte = -1
                word -= 1
            #Otherwise there's still room to go backwards in the word itself
            else:
                byte -= 1
    #Expecting the key to be larger than all 255 if we reached here but who really knows what's possible
    #Coding is magic like that
    except Exception as e:
        print("The key is probably full, but here's the exception so you can see for yourself. The prior key will be used again.")
        print(e)
        return key

    #So the index at word[key][byte] should be increased by one
    #Every byte after that should be set to 0
    key[word][byte] += 1
    #If there are any whole words overflowed to 0
    for w in range(-1, word, -1):
        key[w] = GF([0, 0, 0, 0])
    #Then look at the bytes in the word changed to check for overflow
    for b in range(-1, byte, -1):
        key[word][b] = 0

    #Return the key increased by 1
    return key
#=====================================================


#TESTING BLOCKS
'''
#Test key A (all 0s)
testKeyA = np.full((8, 4), 0)

#Test key B (crosses a word boundary - otherwise all 150)
testKeyB = np.full((8, 4), 150)
testKeyB[-1] = [255, 255, 255, 254]

#Test key C (crosses one byte - otherwise all 128)
testKeyC = np.full((8, 4), 128)
testKeyC[-1] = [128, 128, 128, 254]

#Test key D-F (completely random)
testKeyD = AES.inKeyGen(256)
testKeyE = AES.inKeyGen(256)
testKeyF = AES.inKeyGen(256)

#Tuple of all keys
allKeys = (testKeyA, testKeyB, testKeyC, testKeyD, testKeyE, testKeyF)

#Open a file to write all data to
with open("testKeys.csv", "w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    for i, testKey in enumerate(allKeys):
        print("Currently computing test "+str(i+1)+"...\n"+str(i)+"/6 tests completed")
        writer.writerow(("TEST START", "NO. "+str(i)))
        writer.writerows(seqFill(300, testKey))
        writer.writerow(("TEST END", "NO. "+str(i)))
        print("Test "+str(i+1)+" complete.")
'''






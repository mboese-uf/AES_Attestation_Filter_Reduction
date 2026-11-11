
#Imports
import numpy as np
import math
#Galois is a numpy extension that efficiently handles math in a finite field
#Galois citation: 
# Hostetter, M. (2020). Galois: A performant NumPy extension for Galois fields [Computer software]. https://github.com/mhostetter/galois
import galois
#==================================================================================================
#GLOBAL GALOIS
#Create the finite field for conducting operations in
#The irreducible polynomial from Section 4.2 is explicitly defined
#Hexadecimal of the irreducible polynomial is 11B
GF = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
#==================================================================================================

#Create a method to convert lists of bytes to an array of 4X4 int arrays that can be inputted into the cipher method
def listToBlocks(inList):
    #The size of the list will determine the size of the array needed
    nb = len(inList)
    #The number of blocks needed is nb/16 rounded up
    blocks = math.ceil(nb/16)
    #The array will be a blocks length array of 4x4 arrays
    #For the galois library to work, the data type must be integers
    #The block is filled with 0s because in UTF-8 0000 is the NULL character
    inputBlocks = np.zeros((blocks, 4, 4), dtype=int)

    #Iterate through every index going top to bottom to input the bytes
    for i in range(blocks):
        #The blocks are filled by columns first, then rows, which is why x and y are reversed
        for y in range(4):
            #Make sure the bytes object isn't empty
            if not inList:
                break
            for x in range(4):
                #If the byte object is empty, escape the loop
                if not inList:
                    break
                #Set the btye in the block to the next byte from the original string
                inputBlocks[i][x, y] = inList.pop(0)
    
    #Return the array of blocks
    return inputBlocks
#==================================================================================================


#Create a method to convert strings to an array of 4X4 int arrays that can be inputted into the cipher method
def stringToBlocks(inString):
    #The method to get the btye object representation of a string is .encode
    byteRep = inString.encode('utf-8')
    #The size of the btye object will determine the size of the array needed
    nb = len(byteRep)
    #The number of blocks needed is nb/16 rounded up
    blocks = math.ceil(nb/16)
    #The array will be a blocks length array of 4x4 arrays
    #For the galois library to word, the data type must be integers
    #The block is filled with 0s because in UTF-8 0000 is the NULL character
    inputBlocks = np.zeros((blocks, 4, 4), dtype=int)

    #Iterate through every index going top to bottom to input the bytes
    for block in inputBlocks:
        #The blocks are filled by columns first, then rows, which is why x and y are reversed
        for y in range(4):
            #Make sure the bytes object isn't empty
            if not byteRep:
                break
            for x in range(4):
                #If the byte object is empty, escape the loop
                if not byteRep:
                    break
                #Set the btye in the block to the next byte from the original string
                block[x, y] = byteRep[0]
                #Remove the byte that was just added
                byteRep = byteRep[1:]

    #Return the array of blocks
    return inputBlocks
#==================================================================================================

#Initial key generation for AES-128, AES-192, or AES-256
#Typically, this would be done according to FIPS standards and using approved RBGs under NIST guidelines,
#   but this code does not have risk of key generation attacks
#Instead, a simple random generator will be used
def inKeyGen(size):
    #AES 128 uses a 128 bit key, AES 192 uses a 192 bit key, and AES 256 uses a 256 bit key
    #They will be segmented into 4 byte "word" blocks for use with key expansion
    #Therefore, the output array will be a size/8*4 array of 8 byte arrays
    inKey = np.empty((int(size/32), 4), dtype = int)
    #Go through each word and byte to fill with a random byte
    for i in range(len(inKey)):
        for j in range(4):
            #A byte in integer form can be anywhere from 0 to 255
            inKey[i, j] = np.random.randint(0,256)
    #Return the generated key
    return inKey
#==================================================================================================

#Rotword is a method used in key expansion
#Each byte is rotated to the left one index in the word
#It is explained in section 5.2 of the NIST AES Document
def rotWord(word):
    #Create a new word to move bytes to
    wordP = np.empty(4, dtype=int)
    #Move the byte at index 0 to index 3
    wordP[3] = word[0]
    #Go through each other byte and move it to a new spot
    for i in range(1, 4):
        wordP[i-1] = word[i]
    #Return the rotated word
    return wordP
#==================================================================================================

#Subword is a method used in key expansion
#It uses the SBox from section 5.1.1 Table 4 from the NIST AES pdf
def subWord(word):
    #Defining the constant SBox (substitution table)
    #Values taken from NIST AES Section 5.1.1 Table 4. SBOX() substitution values
    #This is written in hexadecimal but the type is set to ints for use with the galois library
    sBox = np.array([
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]], dtype=int)
    
    #Go through every byte in the word
    for i in range(4):
        #Get the byte from the index
        byte = int(word[i])
        #Get the y value for the sBox
        sBoxY = math.floor(byte/16)
        #Get the x value for the sBox
        sBoxX = byte%16
        #Replace the byte with the new byte from the sBox
        word[i] = sBox[sBoxX, sBoxY]
    #Return the now substituted word
    return word
#==================================================================================================

#Key expansion is used to expand the key to generate more "words"
#It's specifically required for the add round key function that needs 4 "words" per round
#The specifications for this method are in the NIST AES pdf section 5.2
#Key is a linear array of "words", nr is the number of rounds
def keyExpansion(key, nr):
    #Initialize a value for use of the table j[i] with all 0s. 
    #j[0] will be set to the correct value upon being called
    #j[i] is explained in Table 5 of section 5.2
    j = GF(np.array([0, 0, 0, 0],  dtype=int))
    #Convert the key array into a GF field array
    key = GF(key)
    #Create an array of "words" to store the key in
    #The first values of the key are the key itself
    expKey = key
    #Get the length of the key for use in algorithms
    nk = len(key)

    #The algorithm repeats to fill up the key to the size 
    for i in range(len(key), 4*nr+4):
        #Get the last word to use in preperation for the algorithm
        last = expKey[i-1].copy()
        #If i is a multiple of nk...
        if i%nk==0:
            #... rotate the last word, use subWord on the rotation, and add j[i/nk]
            j[0] = int(2**(i/nk))
            last = np.add(GF(subWord(rotWord(last))), j)
        #Otherwise, if Nk is bigger than 6 and i mod Nk is 4...
        elif (nk > 6) and (i%nk == 4):
            #...Apply subWord to the last word
            last = (GF(subWord(last)))
        #The new word becomes the i-nk word + the temp word with any transformations it underwent
        newWord = np.add(expKey[i-nk], last)
        expKey = np.vstack((expKey, newWord))

    #Return the expanded key
    return expKey
#==================================================================================================

#Sub btyes mathematically substitutes each byte in the block with another
#Outlined in NIST AES pdf under section 5.1.1
#Both a substitution table and a mathematical formula is defined, the substitution table
def subBytes(block):
    gfBlock = GF(block)

    #Defining the constant SBox (substitution table)
    #Values taken from NIST AES Section 5.1.1 Table 4. SBOX() substitution values
    #This is written in hexadecimal but the type is set to ints for use with the galois library
    sBox = np.array([
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]], dtype=int)

    #Go through each byte in the block to apply the substitution
    for x in range(4):
        for y in range(4):
            #Find the byte in the block
            byte = int(gfBlock[x, y])
            #Get the x index for the sBox
            sBoxX = math.floor(byte/16)
            #Get the y index for the sBox
            sBoxY = byte%16
            #Replace the byte in gfBlock with the byte from the substitution table
            gfBlock[x, y] = int(sBox[sBoxX, sBoxY])

    #Return the substituted block 
    return gfBlock
#=================================================================================================

#Computes the result of mixColumns as described in NIST AES 5.1.3
#Multiplication function is handled by Galois library and explained in NIST AES Section 4.2
#Output bytes are defined by the function in Section 5.3, operations are performed by column
def mixColumns(block):
    #Format the block into the field
    gfBlock = GF(block)

    #The word used for generation and the resulting output is in section 5.1.3, generation is further explained in section 4.3
    #Resulting matrix is [[0x02, 0x03, 0x01, 0x01],[0x01, 0x02, 0x03, 0x01],[0x01, 0x01, 0x02, 0x03],[0x03, 0x01, 0x01, 0x02]]
    #Galois library only takes np int arrays, so the matrix has been reformatted accordingly
    #Initialize fixed multiplication matrix
    fixedBlock = GF(np.array([[2, 3, 1, 1],[1, 2, 3, 1],[1, 1, 2, 3],[3, 1, 1, 2]], dtype=int))
    
    #Initialize an empty matrix to fill with new values
    gfBlockP = np.empty((4, 4), dtype=int)
     #Multiply the two matrices column by column
    for i in range(4):
        gfBlockP[:, i] = np.matmul(fixedBlock, gfBlock[:, i])

    #Return the new gfBlock
    return gfBlockP
#=================================================================================================

#Shift rows is an invariable function that moves each row in s by a predetermined amount
#s0 is shifted left 0 times
#s1 is shifted left 1 time
#s2 is shifted left 2 times
#s3 is shifted left 3 times
def shiftRows(block):
    #Initialize a duplicate array to move bytes to (block becomes blockP)
    blockP = np.copy(block)
    #Perform shift rows operation on block row indexes 1, 2, and 3
    for i in range(1, 4):
        #Values are moved from each index in block to blockP
        for j in range(4):
            #Overflow condition for new index
            newJ = (j-i) if (j-i >= 0) else 4+(j-i)
            #Reassignment            
            blockP[i, newJ] = block[i, j]
    #Return the new shifted block, blockP
    return blockP
#==================================================================================================

#Add round key is a transformation that relies on the random key generation and key expansion
#It adds the round key w[round*4+c] to the current block word, where c is the column in the block
#This method is outlined in section 5.1.4 of the NIST AES pdf
def addRoundKey(keyW, block, r):
    #Make sure everything is in the GF 2^8 field
    keyW = GF(keyW)
    block = GF(block)

    #Go through each index in the block to apply the addition to
    for x in range(4):
        #y is the column
        for y in range(4):
            #Add the byte to the corresponding byte in the key, [r*4+column, row#]
            block[x, y] += keyW[r, y]

    #Return the now modified block
    return block
#==================================================================================================

#Inverse shift rows is the inverse method of shift rows (Section 5.3.1 in the NIST AES pdf)
#Rows are shifted to the right instead of the left
#This method has been modified to use and update an active coordinate tracker
def invShiftRows(block, target):
    #Initialize a copy of the block array to move bytes to (block becomes blockP)
    blockP = np.copy(block)
    #Initialize a copy of the target list to add the new target indices to
    targetP = target
    #Perform shift rows operation on block row indexes present in the target
    for i in range(0,4):
        #Values are moved from each index in block to blockP
        for j in range(4):
            #Overflow condition for new index
            newJ = (j+i) if (j+i < 4) else (i+j)-4
            #Reassignment            
            blockP[i, newJ] = block[i, j]
    #Return the new shifted block
    return blockP
#==================================================================================================

#Inverse sub bytes is the same method as shift bytes but with an inversed substitution table
#This method has been slightly modified to cross reference an "active coordinate" list to decide what bytes to operate on
#Inverse sub bytes is described in Section 5.3.2 of the NIST AES pdf
def invSubBytes(block):

    #Defining the constant SBox (substitution table)
    #Values taken from NIST AES Section 5.3.2 Table 6. INVSBOX() substitution values
    #This is written in hexadecimal but the type is set to ints for use with the galois library
    sBox = np.array([
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

    gfBlock = GF(block)
    #Go through each byte in the block to apply the substitution
    for x in range(4):
        for y in range(4):
            #Find the byte in the block
            byte = int(gfBlock[x, y])
            #Get the x index for the sBox
            sBoxX = math.floor(byte/16)
            #Get the y index for the sBox
            sBoxY = byte%16
            #Replace the byte in gfBlock with the byte from the substitution table
            gfBlock[x, y] = int(sBox[sBoxX, sBoxY])

    #Return the now substituted gfBlock
    return gfBlock
#==================================================================================================

#Inverse mix columns is multiplies each byte by a value that results in the inverse of mix columns
#The new multiplication table is outlined in Section 5.3.3 of the NIST AES pdf
#This method is modified to work with a list of "active coordinates"
def invMixColumns(block, target):

    #The word used for generation and the resulting output is in section 5.1.3, generation is further explained in section 4.3
    #Resulting matrix is [[0x0e, 0x0b, 0x0d, 0x09],[0x09, 0x0e, 0x0b, 0x0d],[0x0d, 0x09, 0x0e, 0x0b],[0x0b, 0x0d, 0x09, 0x0e]]
    #Galois library only takes np int arrays, so the matrix has been reformatted accordingly
    #Initialize fixed multiplication matrix
    fixedBlock = GF(np.array([[0x0e, 0x0b, 0x0d, 0x09],[0x09, 0x0e, 0x0b, 0x0d],[0x0d, 0x09, 0x0e, 0x0b],[0x0b, 0x0d, 0x09, 0x0e]], dtype=int))
    
    #Format the block into the field
    gfBlock = GF(block)
    
    #Initialize an empty matrix to fill with new values
    gfBlockP = np.empty((4, 4), dtype=int)
    #Multiply the two matrices column by column
    for i in range(4):
        gfBlockP[:, i] = np.matmul(fixedBlock, gfBlock[:, i])

    #Return the new gfBlock
    return gfBlockP
    
#==================================================================================================

#Cipher runs all operations on an input for a number of rounds dependent on the key length
#Cipher also includes prerounding and post-rounding operations
#The input is a 2D array of size 128 bits, or 16 bytes.
#Other required parameters are an unexpanded key, and the number of rounds
#Cipher is explained in section 5.1 of the NIST AES pdf
def cipher(input, key, r):
    #Define a state that is the input in the GF 2^8 field
    state = GF(input)
    #Expand the key
    eKey = GF(keyExpansion(key, r))

    #Preround by adding the round key words 0-3
    state = addRoundKey(eKey,state, 0)

    #Run a loop of algorithms from 1 to rounds-1 times
    for i in range(1, r):
        state = subBytes(state)
        state = shiftRows(state)
        state = mixColumns(state)
        state = addRoundKey(eKey, state, i)

    #Run the last round without mix columns
    state = subBytes(state)
    state = shiftRows(state)
    state = addRoundKey(eKey, state, r)

    #Return the encrypted block
    return state
#==================================================================================================

#Inverse Cipher is outlined in section 5.3 of the NIST AES pdf
#It runs all operations to un-encrypt a message using a key
#The input is a 2D array of size 128 bits, or 16 bytes.
#Other required parameters are an expanded key, and the number of rounds
#Note there is no invAddRoundKey because the round key is its own inverse
def invCipher(input, key, r, expanded=False):
    #Define a state that is the input in the GF 2^8 field
    state = GF(input) 
    #Expand the key
    if not expanded:
        eKey = GF(keyExpansion(key, r))
    else:
        eKey = key

    #Add the last word in the round key
    state = addRoundKey(eKey, state, r)
    #Repeat the inverse cipher method loop until round is 1
    #Note that we are working backwards, so the current round will be r-i for some methods
    #Since this is the unmodified inverse cipher, target is set to None
    for i in range(1, r):
        state = invShiftRows(state, None)
        state = invSubBytes(state)
        state = addRoundKey(eKey, state, r-i)
        state = invMixColumns(state, None)

    #The last round is a bit different and does not perform mixColumns
    state = invShiftRows(state, None)
    state = invSubBytes(state)
    state = addRoundKey(eKey, state, 0)

    #Return the un-encoded block
    return state
#==================================================================================================

#Reformat a block to a list in order
def reformat(block):
    #Create a list to put the values into
    blockList = []
    #Go through each row and column
    for col in range(4):
        for row in range(4):
            blockList.append((block[row][col]))

    blockList = GF(blockList)
                             

    #Return the list
    return blockList
#====================================================================================================

#O-AES encryption method
#Obfuscated AES makes "true messages" get added to unattested
#ptBlock is the plaintext message to be converted to a block
#Attest Data is the dictionary of data that contains a dictionary of n dimensional matrices
#   For this purpose, the unigrams list will be used
def oAESCipher(message, key, r, attestData):
    #Encode the message into a string of bytes
    mesBytes = list(message.encode("utf-8"))
    #Chose a random position to add a byte for every block that will be made in the message
    randPosList = []
    #Calculate the number of bytes that will be needed
    #1 per every 16 bytes in the message, plus 1 more for every 16
    required = math.ceil(len(mesBytes)/16)
    required += math.ceil(required/16)
    for i in range(required):
        #Values will be between 0 and 16 bytes (the length of a block)
        #This works with the below that pops the blocks from mesBytes as it works
        randPosList.append(np.random.randint(0, 16))
    #Chose 16 random UNATTESTED bytes (keep selecting random bytes until 16 false values are found)
     #Create a way to store the new message, which starts with the random bytes
    newMess = []
    while len(newMess)<16:
        #Values are between 0 and 255
        randomUnattested = int(np.random.randint(0, 255))
        if not attestData["unigrams"][randomUnattested]:
            newMess.append(randomUnattested)

    #Add random bytes at each position selected randomly from randBytes
    for pos in randPosList:
        #Pop the first pos number of bytes from mes list
        poppedBytes = mesBytes[:pos]
        mesBytes[:pos] = []
        #Add those to new mess
        newMess.extend(poppedBytes)
        #Then, select a random value from the first 16 bytes of newMess to add
        toAddByte = int(np.random.choice(newMess[:16]))
        newMess.append(toAddByte)
        #Finally, add the final x bytes to complete a block to the message
        #With the random byte, the number to be added to make a block is 16-pos then subtract another 1
        poppedBytesEnd = mesBytes[:(16-pos)-1]
        mesBytes[:(16-pos)-1] = []
        newMess.extend(poppedBytesEnd)

    #With the new message, convert it into its blocks, then encrypt following normal protocol
    newBlocks = listToBlocks(newMess)
    #Encrypt
    encryptedBlocks = []
    for i in range(len(newBlocks)):
        encryptedBlocks.append(cipher(newBlocks[i].copy(), key.copy(), r))

    #Return the list of encrypted oAES blocks
    return encryptedBlocks
#====================================================================================================


##O-AES decryption method
#Obfuscated AES makes "true messages" get added to unattested
#encryptList is the list of blocks encrypted using oAES
#The first block is the list of all unattested bytes
def oAESInvCipher(encryptList, key, r):
    #Decrpyt the first block to get all the unattested values from
    unattestBlock = invCipher(encryptList.copy()[0], key.copy(), r)
    #Reformat into a list of values to not be added
    unattestValues = reformat(unattestBlock)
    #Remove the first item from the encryptList
    encryptList = encryptList[1:]
    #Create a list of decrypted values
    decryptList = []
    #Go through each block
    for block in encryptList:
        #Decrypt the block and reformat it
        decrypted = invCipher(block.copy(), key.copy(), r)
        decrypted = reformat(decrypted)
        #For each value in decrypted, add it to decrypt list if it is not in unattest values
        for val in decrypted:
            if val not in unattestValues:
                decryptList.append(val)

    #Change the list to a string
    originalMessage = (bytes(decryptList)).decode("utf-8")

    #Return the original message
    return originalMessage
#====================================================================================================



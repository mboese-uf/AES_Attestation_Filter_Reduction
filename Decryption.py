#Imports
#Galois citation: 
# Hostetter, M. (2020). Galois: A performant NumPy extension for Galois fields [Computer software]. https://github.com/mhostetter/galois
import galois
import numpy as np
import AES
import time
import KeyFill
import ast
import csv
from tqdm import tqdm
import sys
import threading
import os
#==================================================

#METHOD TO GET GLOBAL ATTEST FILE VARIABLE
#Load the attestation file in
def loadAttest(fileName):
    #Make a dictionary that stores 4 arrays of True/False data
    attestData = {"unigrams": np.full(256, True, dtype=bool), 
                  "bigrams": np.full((256, 256), True, dtype=bool), 
                  "trigrams": np.full((256, 256, 256), True, dtype=bool),
                  "fourgrams": np.full((256, 256, 256, 256), True, dtype=bool)}
    #Open the csv file
    with open(fileName, "r", newline="", encoding="utf-8") as data:
        #Make a csv reader
        reader = csv.reader(data)
        #Skip the header
        next(reader)
        #Go through each row
        for i, row in tqdm(enumerate(reader)):
            #Check the values in each index (make sure they aren't empty)
            if row[1] != "":
                row1 = int(row[1])
                attestData["unigrams"][row1] = False
            if row[2] != "":
                row2 = ast.literal_eval(row[2])
                attestData["bigrams"][row2[0]][row2[1]] = False
            if row[3] != "":
                row3 = ast.literal_eval(row[3])
                attestData["trigrams"][row3[0]][row3[1]][row3[2]] = False
            if row[4] != "":
                row4 = ast.literal_eval(row[4])
                attestData["fourgrams"][row4[0]][row4[1]][row4[2]][row4[3]] = False

            #FOR TESTING
            #if i > 500000:
                #break

    #0 is possible as a null value in unigram - set it to true
    attestData["unigrams"][0] = True
    
    #Return the dictionary
    return attestData
#===================================================
#GLOBAL ATTEST FILE
attestFile = None
#Determine language being used
language = None
#Check for chinese
if sys.argv[2] == "zh" or sys.argv[2] == "ZH":
    language = "zh"
    attestFile = loadAttest("UnattestedByteGrams_zh.csv")
#Check for English
elif sys.argv[2] == "en" or sys.argv[2] == "EN":
    language = "en"
    attestFile = loadAttest("UnattestedByteGrams_en.csv")
#==================================================
#GLOBAL TIMER
#TEST TIME (4 hours = 14400 seconds)
testTime = 14400
endTime = time.monotonic()+testTime
#Give the oAES 5 minutes
oTestTime = 300
#==================================================
#GLOBAL VALUES, SEED, AND LOCKS
np.random.seed(42)
badKeyEvent = threading.Event()
keyLock = threading.Lock()
currentKey = np.zeros((8, 4))
stateList = []
keyDict = {True: [], False: []}
#Create the finite field for conducting operations in
#The irreducible polynomial from Section 4.2 is explicitly defined
#Hexadecimal of the irreducible polynomial is 11B
GF = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
#==================================================

#Single thread of decryption
#Returns the state and a bool (true = attested data, false = unattested data)
#nr is 14 for AES256
def singleDecrypt(key, initial, nr=14):
    #Grab globals
    global stateList
    global attestFile
    #Fill the key
    ekey = KeyFill.reverseFill(key)

    endState = AES.invCipher(initial, ekey, nr, expanded=True)

    isAttestedBlock = isAttested(attestFile, endState)
    return endState, isAttestedBlock
#==================================================

#Method to calculate one round of AES
def oneRound(input, eKey, round, totalRounds):
    #Define a state that is the input in the GF 2^8 field
    state = GF(input) 

    #CODE COPY PASTED FOR ONE ROUND FORMAT FROM AES.py invCipher
    if round==totalRounds:
        #The last round is a bit different and does not perform mixColumns
        state = AES.invShiftRows(state, None)
        state = AES.invSubBytes(state)
        state = AES.addRoundKey(eKey, state, 0)

    #When not at the last round, use mixColumns
    else:
        if round==1:
            #On the first round, add the roundKey
            state = AES.addRoundKey(eKey, state, totalRounds-round)
        #The standard round for invCipher
        state = AES.invShiftRows(state, None)
        state = AES.invSubBytes(state)
        state = AES.addRoundKey(eKey, state, totalRounds-round)
        state = AES.invMixColumns(state, None)

    #Return the state at the end of the round
    return state

#===================================================

#Give the method the current calculated state and all calculated states to determine if there is a match
#ks is the key size (determines how many blocks must match to be a true match)
#stateList is in the form [([np array], True/False), ]
def checkMatch(current, stateList, ks=8):
    #Assume no match
    isMatch = False
    #Is attested is None unless there is a match
    isAttested = None
    #Check for the first block in calculated
    for allBlocks in stateList:
        for i, block in enumerate(allBlocks[0]):
            if np.array_equal(current[0], block):
                #Counter for how many blocks have been checked and match (currently 1)
                checked = 1
                #While there is a match, continue searching down the key until keySize blocks back have been checked
                try:
                    while checked-i > 0 and np.array_equal(current[checked], allBlocks[i-checked]):
                        checked+=1
                        #If the number of blocks checked is ks and they all match, match is true
                        if checked == ks:
                            isMatch = True
                            #Check if the match is attested or unattested
                            isAttested = allBlocks[1]
                            break
                except IndexError:
                    pass
                except Exception as e:
                    print("Wow something went really wrong while checking for a match and it wasn't what I expected (out of bounds)")
                    print(e)


    #Return match
    return isMatch, isAttested
#===================================================

#Look to see if the final block is theoretically attested
#Note the minute an unattested match is found, method returns false
#!!!FALSE means the block contains an unattested block!!!
def isAttested(attestData, block):
    #Reformat the block into a list using AES.py reformat method
    mesList = AES.reformat(block)
    #For every byte check if its index in unattested unigrams is marked as unattested
    for byte in mesList:
        if not attestData["unigrams"][byte]:
            return False
    #Then check bigrams
    for bibyte1, bibyte2 in zip(mesList, mesList[1:]):
        if not attestData["bigrams"][bibyte1][bibyte2]:
            return False
    #Then check trigrams
    for tribyte1, tribyte2, tribyte3 in zip(mesList, mesList[1:], mesList[2:]):
        if not attestData["trigrams"][tribyte1][tribyte2][tribyte3]:
            return False
    #Finally, check fourgrams
    for fourbyte1, fourbyte2, fourbyte3, fourbyte4 in zip(mesList, mesList[1:], mesList[2:], mesList[3:]):
        if not attestData["fourgrams"][fourbyte1][fourbyte2][fourbyte3][fourbyte4]:
            return False
    #If there were no matches in the unattested file and the end of the method is reached, the method returns true
    return True
#===================================================

#Multithread decyption method
def decryptTask(initial, correctKey, nr=14):
    #Grab globals
    global endTime
    global badKeyEvent
    global currentKey
    global stateList
    global keyDict
    
    #Only operate while time isn't out
    while (time.monotonic() < endTime) and (not badKeyEvent.is_set()):
        #Use lock to prevent duplicate key tests
        with keyLock:
            #Increase the key by one
            currentKey = KeyFill.increaseKeyOne(currentKey.copy())
            #Give a copy to the thread worker
            workerKey = currentKey.copy()
        #Run the decryption method and append the results to stateList, then return the key and result to add to the global key dictionary
        entireState, attestation = singleDecrypt(workerKey, initial, nr=nr)
        #Make sure a match wasn't found - matches are not appended to the entire state list
        if entireState is not None:
            stateList.append((entireState, attestation))
        #Append the key to the correct side
        keyDict[attestation].append(workerKey)
        #Check to make sure the real key hasn't been added to false
        if not attestation and np.array_equal(correctKey, workerKey):
            print("CORRECT KEY ADDED TO FALSE")
            badKeyEvent.set()
            break
        elif np.array_equal(correctKey, workerKey):
            print("CORRECT KEY ADDED TO ATTESTATION = TRUE")
#===================================================

#RUN TEST METHOD
def runTest(initialMessage):
    global currentKey
    print("==============================\nBeginning test with new key and message")
    currentKey = AES.inKeyGen(256)
    trueKey = KeyFill.increaseKeyOne(currentKey.copy())
    #Key must be filled from reverse
    fromReverseTK = KeyFill.reverseFill(trueKey)
    fromReverseTK = fromReverseTK[0:8]
    testBlock = AES.cipher(initialMessage, fromReverseTK, 14)

    threadNum = 8
    for i in range(threadNum):
        t = threading.Thread(target=decryptTask, args=(testBlock, trueKey))
        t.start()


    print("Total possible keys found: "+str(len(keyDict[True])))
    print("Total impossible keys found: "+str(len(keyDict[False])))
#===================================================

#TESTS
#Make sure a language was properly recognized
if language is not None:

    #===================== CREATE LIST OF MESSAGES =====================
    #Make a list to hold 5 messages from the language
    messList = []
    #Get a random integer to start from
    #Max size for a random int selection (-17 because of -1 array rules and 16 bytes are required)
    maxSize = os.path.getsize(sys.argv[1])-17
    #Iterate through each index in the list
    for i in range(5):
        #Choose a random value between 0 and the maxSize
        randomStart = np.random.randint(0, maxSize)
        #Open the file
        with open(sys.argv[1], "r", encoding="utf-8") as file:
            #Starting from the random start point, read 
            file.seek(randomStart)
            randomBytes = file.read(16, encoding="utf-8")
            #Append the message to the list
            messList.append(randomBytes)

    print("Randomly chosen messages are :"+str(messList))
    #================================================================================


    #======================= TEST CHOSEN MESSAGES - NORMAL AES =========================
    
    #Go through each message, run for the alloted test time
    for message in messList:
        endTime = time.monotonic()+testTime
        block = AES.stringToBlocks(message)[0]
        runTest(block)
        badKeyEvent.clear()

    print("\n============================================\n")
    #================================================================================
    


    
    #======================= TEST CHOSEN MESSAGES - O-AES =========================

    #OAES test
    print("\nSTARTING OAES TEST: EXPECTED OUTCOME - ALL CORRECT KEYS ARE ADDED TO FALSE")
    for message in messList:
        endTime = time.monotonic()+oTestTime
        print("\nTesting new OAES message")
        #Change the key
        currentKey = AES.inKeyGen(256)
        trueKey = KeyFill.increaseKeyOne(currentKey.copy())
        #Key must be filled from reverse
        fromReverseTK = KeyFill.reverseFill(trueKey)
        fromReverseTK = fromReverseTK[0:8]
        obfuscatedBlocks = AES.oAESCipher(message, fromReverseTK, 14, attestFile)
        #For each block, try to decrypt it with decrypt task
        for block in obfuscatedBlocks:
            decryptTask(block, trueKey)
        badKeyEvent.clear()

    #================================================================================

#Language failsafe
else:
    print("INVALID LANGUAGE AT SYS ARG 2") 


#Imports
import sys
import numpy as np
import pandas as pd
#==========================================================

#Get unigram byte attestation data
def getAttestation(file):
    #Open the text file
    with open(file, "r", encoding="utf-8") as allText:
        #Go through each line in the file
        for line in allText:
            #Transform the line into byte form
            byteLine = line.encode(encoding="utf-8")
            #Make a 1D NP array that is the size of all possible unigram byte representations
            #Autoset all attestation to false - will become true when data is found
            isAttestedUnigram = np.full(256, False, dtype=bool)
            #Do the same for bigrams, trigrams, and 4 grams
            isAttestedBigram = np.full((256, 256), False, dtype=bool)
            isAttestedTrigram = np.full((256, 256, 256), False, dtype=bool)
            isAttestedFourgram = np.full((256,256,256,256), False, dtype=bool)
            #Go through byteLine, set its index in isAttested to True
            for val1, val2, val3, val4 in zip(byteLine, byteLine[1:], byteLine[2:], byteLine[3:]):
                isAttestedUnigram[val1] = True
                isAttestedBigram[val1][val2] = True
                isAttestedTrigram[val1][val2][val3] = True
                isAttestedFourgram[val1][val2][val3][val4] = True

        print("Gathering completed!")

    #Return all the attested ngram tables
    return (isAttestedUnigram, isAttestedBigram, isAttestedTrigram, isAttestedFourgram)

#Padding def for making the test list into a pd dataframe
def padList(gramList, l):
    if len(gramList)<l:
        repeats = l-len(gramList)
        for i in range(repeats):
            gramList.append(None)
    print("Padding complete")
    return gramList

#Create the list of values to look for in the experiment based on what is unattested and unique data
#Unique data means that it contains only atteseted data, but is unattested in its combination
def getTestList(unigrams, bigrams, trigrams, fourgrams):
    #Create list of unigrams to check
    unattestedUnigrams = []
    for i in range(len(unigrams)):
        if not unigrams[i]:
            unattestedUnigrams.append(str((i)))
    print("Unigrams complete")
    #Create list of unique unattested bigrams to check
    unattestedBigrams = []
    for i in range(len(bigrams)):
        #Only go through the second dimension if i is in unigrams
        if unigrams[i]:
            for j in range(len(bigrams[i])):
                #If the second unigram is also attested, but the combination of i and j is not
                #Add (i,j) to the list
                if unigrams[j] and not bigrams[i][j]:
                    unattestedBigrams.append(str((i, j)))
    print("Bigrams complete")

    #Create list of unique unattested trigrams to check
    unattestedTrigrams = []
    for i in range(len(trigrams)):
        #Only go through the second dimension if i is in unigrams
        if unigrams[i]:
            for j in range(len(trigrams[i])):
                #Only go through the third dimension if i,j is in bigrams
                if bigrams[i][j]:
                    for k in range(len(trigrams[i][j])):
                        #If j and k is in bigrams, but ijk is not in trigrams
                        #Add i,j,k to the list
                        if bigrams[j][k] and not trigrams[i][j][k]:
                            unattestedTrigrams.append(str((i, j, k)))
    print("Trigrams complete")
    
    #Create list of unique unattested 4grams to check
    unattestedFourgrams = []
    for i in range(len(fourgrams)):
        #Only go through the second dimension if i is in unigrams
        if unigrams[i]:
            for j in range(len(fourgrams[i])):
                #Only go through the third dimension if i,j is in bigrams
                if bigrams[i][j]:
                    for k in range(len(fourgrams[i][j])):
                        #Only go through the fourth dimension if i,j,k is in trigrams
                        if trigrams[i][j][k]:
                            for l in range(len(fourgrams[i][j][k])):
                                #If j,k,l is in trigrams but i,j,k,l is not in fourgrams
                                #Add (i,j,k,l) to the list
                                if trigrams[i][j][k] and not fourgrams[i][j][k][l]:
                                    unattestedFourgrams.append(str((i, j, k, l)))
    print("Fourgrams complete")

    #Make all lists the same length
    longest = max((len(unattestedUnigrams),len(unattestedBigrams),len(unattestedTrigrams), len(unattestedFourgrams)))
    unattestedUnigrams = padList(unattestedUnigrams, longest)
    unattestedBigrams = padList(unattestedBigrams, longest)
    unattestedTrigrams = padList(unattestedTrigrams, longest)
    unattestedFourgrams = padList(unattestedFourgrams, longest)

    #Make a dataframe out of the four lists to return and save as CSV
    allUnattestations = pd.DataFrame({"Unigrams" : unattestedUnigrams, "Bigrams" : unattestedBigrams, "Trigrams" : unattestedTrigrams, "4-grams" : unattestedFourgrams})
    allUnattestations.to_csv("UnattestedByteGrams.csv")
    print("File created")


unigrams, bigrams, trigrams, fourgrams = getAttestation(sys.argv[1])
getTestList(unigrams, bigrams, trigrams, fourgrams)
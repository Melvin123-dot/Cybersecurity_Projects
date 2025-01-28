'''
This code defines a function translate that takes a string phrase as input and returns a new string where all the vowels 
(a, e, i, o, u) in the original string are replaced with the letter "g" or "G". The case of the "g" matches the case of 
the original vowel (i.e., uppercase vowels are replaced with "G", lowercase vowels are replaced with "g").
'''

'''
The code defines the translate function with it's parameter called phrase. The "translation="" this line initializes an 
empty string translation that will be used to build the translated phrase. The for loop for letter in phrase: iterates 
over each character in the input phrase. if letter.lower() in "aeiou": This line checks if the current character, 
converted to lowercase, is a vowel. If the current character is an uppercase vowel (checked using letter.isupper()), 
it is replaced with "G" (translation = translation + "G").  If the current character is a lowercase vowel, it is 
replaced with "g" (translation = translation + "g"). If the current character is not a vowel, it is added to 
translation as is (translation = translation + letter). After all characters in phrase have been processed, the function returns the translation.
The line print(translate(input("Enter a phrase: "))) asks the user to enter a phrase, translates it using the translate function, 
and then prints the result.
So, if you run this code and input the phrase “Hello, World!”, the output will be “Hgllg, Wgrld!”.
'''

def translate (phrase):
    translation = ""
    for letter in phrase:
        if letter.lower() in "aeiou":
            if letter.isupper():
                translation = translation + "G"
            else: 
                translation = translation + "g"
        else:
            translation = translation + letter
    return translation

print(translate(input("Enter a phrase: ")))
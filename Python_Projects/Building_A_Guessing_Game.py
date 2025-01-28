secret_word = "giraffe" #This defines the variable secret word with the value "giraffe"
guess = "" #This line of code tells the machine that it's an empty string for which it may require the user to input some data when asked.
#This block of code set's a limt to how many times the user can guess the word and if the user reaches the guess limit the code will print out
#the statement "out of guesses" which has boolean value of false.
guess_Count = 0 
guess_Limit = 3
out_of_Guesses = False

'''
The block of code below tells the machine to iterate through the given loops such that if the user is not out of guesses yet it should keep
on with the guess until it reaches it's limit and each guess it makes a counter is set to 1 to make it increase in order to get to it's limit
and then prints out the statement using the boolean value True to signify the user is out of guesses else if the user guess the secret_word right
then it should iterate to the else statement printing out "You win!" 
'''
while guess != secret_word and not(out_of_Guesses):
    if guess_Count < guess_Limit:
       guess = input("Enter  guess: ")
       guess_Count += 1
    else:
        out_of_Guesses = True
if out_of_Guesses:
    print("Out of Guesses, You Lose! ")
else:
    print("You win! ")
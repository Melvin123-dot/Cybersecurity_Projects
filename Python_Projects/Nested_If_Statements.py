def greeting():
    return "Welcome to the rock paper scissors game!"

response = greeting()
print(response)


def get_choices():
    player_choice = input(("Enter a choice (rock, paper, scissors):"))
    computer_choice = "paper"
    choices = {"player": player_choice, "computer": computer_choice}
    
    return choices

def check_win(player, computer):
    print(f"player choose {player} computer choose {computer}")
    if player == computer:
        return "It's a tie!"
    elif player == "rock":
        if computer == "scissors":
            return "Rock smashes scissors! You win!"
        else:
            return "Paper covers rock! You lose."
    elif player == "paper":
        if computer == "rock":
              return "Paper covers rock! You win!"
        else:
            return "Scissors cuts paper! You lose."
    elif player == "scissors":
        if computer == "paper":
            return "Scissors cuts paper! You win!"
        else:
            return "Rock smashes scissors! You lose." 
        

choices = get_choices()
result = check_win(choices["player"], choices["computer"])
print(result)

    
def greeting():
    return "Welcome to the rock paper scissors game!"

response = greeting()
print(response)


def get_choices():
    player_choice = input(("Enter a choice (rock, paper, scissors:"))
    computer_choice = "paper"
    choices = {"player": player_choice, "computer": computer_choice}
    
    return choices

def check_win(player, computer):
    print(f"player choose {player} computer choose {computer}")
    if player == computer:
        return "It's a tie!"
    elif player == "rock" and computer == "scissors":
        return "Rock smashes scissors! You win!"
    elif player == "rock" and computer == "paper":
        return "Paper covers rock! You lose!"
    elif player == "paper" and computer == "scissors":
        return "Scissors cuts paper! You win!"
    else:
        return "Sorry you didn't understand this game!"
        
    
check_win("rock", "paper")
    
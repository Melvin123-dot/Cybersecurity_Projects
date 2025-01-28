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
    else:
        return "You loose!"
    
check_win("rock", "paper")
    
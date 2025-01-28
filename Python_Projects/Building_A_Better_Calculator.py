num1 = float(input("Enter first number: ")) #This line of code defines the variable and assigns a float type as number to be entered by the user
op = input("Enter operator: ") #This prompts the user to enter the specified operator given
num2 = float(input("Enter second number: ")) #This line of code defines the variable and assigns a float type as number to be entered by the user

'''
The below code uses a loop conditional statements which tells the machine to iterate through the given operators
when the user enters a specified one meant for the operation
'''

if op == "+":
    print(num1 + num2)
elif op == "*":
    print(num1 * num2)
elif op == "-":
    print(num1 - num2)
elif op == "%":
    print(num1 % num2)
elif op == "/":
    print(num1 / num2)
else:
    print("No Operator used")

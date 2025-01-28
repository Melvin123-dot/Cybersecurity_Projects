#These block of codes puts in a list of values in a nested form or combined form using the defined variable called the number grid
#The number_grid is a list that contains four other lists. The first three inner lists have three elements each, and the fourth one 
#has a single element.
#print(number_grid[0][0]) prints the first element of the first list in number_grid. In Python, list indices start at 0, 
#so number_grid[0][0] refers to the first element of the first listThe for loop nested within another for loop 
#(also known as a nested loop) is used to iterate through each element in the 2-dimensional list.
#The outer loop for row in number_grid: goes through each list in number_grid (each list is considered a ‘row’).
#The inner loop for col in row: goes through each element in the current row.
#print(col) then prints each element.
#So, when you run this code, it will first print 1 (the result of print(number_grid[0][0])), and then it will print each number in the number_grid on a new line, which is 1.

number_grid = [
    [1,2,3],
    [4,5,6],
    [7,8,9],
    [0]
]
print(number_grid[0][0])

for row in number_grid:
    for col in row:
        print(col)
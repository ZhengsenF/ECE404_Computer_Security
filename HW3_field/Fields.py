# Homework Number: 3
# Name: Zhengsen FU
# ECN Login: fu216
# Due Date: Feb 6

def determine(num, mod):
    # the following code is from lecture note
    x, x_old = 0, 1
    y, y_old = 1, 0
    while mod:
        q = num // mod
        num, mod = mod, num % mod
        x, x_old = x_old - q * x, x
        y, y_old = y_old - q * y, y
    if num != 1:
        return False
    else:
        return True


if __name__ == "__main__":
    n_main = eval(input("Please enter an integer that is smaller than 50: "))
    if not(n_main < 50):
        raise ValueError("input value must be smaller than 50")
    if type(n_main) is not int:
        raise TypeError("input value must be an integer")

    field = True
    for lcv in range(1, n_main):
        if not determine(lcv, n_main):
            field = False
            break

    if field:
        print(f"Z{n_main} is a filed")
    else:
        print(f'Z{n_main} is a ring')

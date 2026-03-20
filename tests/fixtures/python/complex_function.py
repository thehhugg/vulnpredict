"""Fixture: contains a function with high cyclomatic complexity and deep nesting."""


def very_complex_function(data, mode, flag, option, extra):
    """A deliberately complex function to test complexity detection."""
    result = []
    if mode == "a":
        if flag:
            for item in data:
                if item > 0:
                    if option == 1:
                        result.append(item * 2)
                    elif option == 2:
                        result.append(item * 3)
                    else:
                        try:
                            result.append(item / extra)
                        except ZeroDivisionError:
                            result.append(0)
                elif item < 0:
                    result.append(abs(item))
                else:
                    result.append(None)
        else:
            for item in data:
                while item > 0:
                    item -= 1
                    if item % 2 == 0:
                        result.append(item)
    elif mode == "b":
        if flag and option:
            result = [x for x in data if x > 0]
        elif flag or option:
            result = [x for x in data if x < 0]
        else:
            result = list(data)
    return result

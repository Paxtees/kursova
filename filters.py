def split_into_lines(text, length):
    lines = [text[i:i+length] for i in range(0, len(text), length)]
    return '\n'.join(lines)

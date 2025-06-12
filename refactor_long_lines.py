import os
import ast
import re

def preserve_strings_and_comments(line, placeholder_prefix="__TEMP_PLACEHOLDER__"):
    """Replaces string literals and comments with placeholders."""
    # Placeholder for comments
    # Regex to find comments (everything after #)
    comment_regex = r"(\#.*)"
    # Placeholder for strings
    # Regex to find f-strings, raw strings, byte strings, triple-quoted strings
    # Corrected string_regex
    _string_parts = [
        r"[urfURF]?[bB]?\"\"\"(?:\\.|[^\"])*?\"\"\"",  # Triple double quotes
        r"[urfURF]?[bB]?'''(?:\\.|[^'])*?'''",    # Triple single quotes
        r"[urfURF]?[bB]?\"(?:\\.|[^\"])*\"",      # Double quotes
        r"[urfURF]?[bB]?'(?:\\.|[^'])*'",       # Single quotes
    ]
    string_regex = r"(" + "|".join(_string_parts) + r")"

    placeholders = {}
    placeholder_idx = 0

    def replacer(match):
        nonlocal placeholder_idx
        original_text = match.group(0)
        placeholder = f"{placeholder_prefix}{placeholder_idx}"
        placeholders[placeholder] = original_text
        placeholder_idx += 1
        return placeholder

    # Replace strings first, then comments
    line = re.sub(string_regex, replacer, line)
    line = re.sub(comment_regex, replacer, line)

    return line, placeholders

def restore_strings_and_comments(line, placeholders):
    """Restores string literals and comments from placeholders."""
    for placeholder, original_text in reversed(list(placeholders.items())): # Restore in reverse to handle nested cases if any
        line = line.replace(placeholder, original_text)
    return line

def reformat_python_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            original_content = f.read()
        # ast.parse(original_content) # Temporarily comment out to force reformatting
        # print(f"File already valid, skipping: {filepath}")
        # return
    # except SyntaxError:
    except Exception: # Catch any error if ast.parse was the issue, or just proceed
        print(f"Reformatting file: {filepath}")
        # Proceed with reformatting
        pass
    except Exception as e:
        print(f"Error reading or parsing file {filepath}: {e}")
        return

# Helper function to recursively split lines
def _recursively_split_line(line_content, base_indent_str, output_lines_list):
    # Preserve strings and comments for the current line_content
    preserved_line, placeholders = preserve_strings_and_comments(line_content)

    # Split by semicolon first
    parts = preserved_line.split(';')

    active_indent_for_current_scope = base_indent_str

    for i, part_preserved_content in enumerate(parts):
        is_last_part = (i == len(parts) - 1)
        if not part_preserved_content.strip():
            if is_last_part and preserved_line.endswith(';'): # Original was "code;"
                pass
            elif not is_last_part: # "foo;;bar"
                pass
            continue

        restored_part_content = restore_strings_and_comments(part_preserved_content, placeholders)
        current_part_base_indent = base_indent_str if i == 0 else active_indent_for_current_scope

        if i == 0:
            processed_content_segment = restored_part_content
        else:
            processed_content_segment = restored_part_content.lstrip()

        content_for_colon_split, local_placeholders = preserve_strings_and_comments(processed_content_segment)
        colon_match = re.match(r"^(\s*(?:class|def)\s+[^:]+:\s*)(.*)", content_for_colon_split)

        if colon_match:
            header = restore_strings_and_comments(colon_match.group(1), local_placeholders)
            body = restore_strings_and_comments(colon_match.group(2), local_placeholders).lstrip()

            appended_line = current_part_base_indent + header
            output_lines_list.append(appended_line)

            active_indent_for_current_scope = current_part_base_indent + "    "

            if body:
                _recursively_split_line(body, active_indent_for_current_scope, output_lines_list)
        else:
            final_segment_content = restore_strings_and_comments(content_for_colon_split, local_placeholders)
            appended_line = current_part_base_indent + final_segment_content
            output_lines_list.append(appended_line)


def reformat_python_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            original_content = f.read()
        ast.parse(original_content)
        print(f"File already valid, skipping: {filepath}")
        return
    except SyntaxError:
        print(f"Reformatting file: {filepath}")
        # Proceed with reformatting
        pass
    except Exception as e:
        print(f"Error reading or parsing file {filepath}: {e}")
        return

    original_lines = original_content.splitlines()
    reformatted_lines_final = []

    for line_content in original_lines:
        original_line_indent = re.match(r"^(\s*)", line_content).group(1) if line_content else ""
        line_content_stripped = line_content[len(original_line_indent):]
        _recursively_split_line(line_content_stripped, original_line_indent, reformatted_lines_final)

    final_content = "\n".join(reformatted_lines_final)

    try:
        ast.parse(final_content)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(final_content)
        print(f"Successfully reformatted: {filepath}")
    except SyntaxError as e:
        print(f"Failed to reformat {filepath} into valid Python. Error: {e}")
        print("The content after initial reformatting was:")
        print(final_content)
        # Optionally, write to a .failed file instead of overwriting with broken code
        # with open(filepath + ".failed", 'w', encoding='utf-8') as f:
        #     f.write(final_content)
        # print(f"Problematic reformatted content saved to {filepath}.failed")


def main():
    target_directory = 'tech-access-platform'
    if not os.path.exists(target_directory):
        print(f"Directory not found: {target_directory}")
        return

    for root, _, files in os.walk(target_directory):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                reformat_python_file(filepath)

if __name__ == '__main__':
    main()

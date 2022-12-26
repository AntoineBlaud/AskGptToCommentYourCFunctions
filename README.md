# AskGptToCommentYourCFunctionsAskGptToCommentYourCFunctions

This project allows you to comment your C functions automatically using OpenAI's GPT-3 language model.
# Requirements

    pyparsing
    openai

# Setup

Set "openai.api_key" with your private api key

# Usage

```
python main.py input_file output_file
```
# Example
```
python main.py input.c output.c
```
Go into example directory to appreciate a result on *frida guminterceptor* . Try to understand the code with and without!

# How it works

The program reads the input C file and uses pyparsing to locate all function definitions. It then sends each function definition to the OpenAI API and receives a description of the function in return. The program then adds the description as a comment above the function definition and writes the modified content to the output file.
Note

This project is currently limited to commenting function definitions only. In a future version, we may also add support for commenting struct definitions.
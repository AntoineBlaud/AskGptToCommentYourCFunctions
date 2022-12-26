import contextlib
import sys
import re
import argparse
import textwrap

# import pyparsing module for parsing C code
from pyparsing import *

# import openai module for using the OpenAI API
import openai

# set OpenAI API key
openai.api_key = ""

def _query_model(query, max_tokens=4096):
    """
    Function which sends a query to davinci-003 and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to davinci-003
    :param cb: Tu function to which the response will be passed to.
    """
    # subtract the length of the query from the maximum number of tokens
    max_tokens = max_tokens - len(query)
    
    # try to send the query to the model
    try:
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=query,
            temperature=0.6,
            max_tokens=max_tokens,
            top_p=1,
            frequency_penalty=1,
            presence_penalty=1,
            timeout=60  #
        )
        response = "\n//".join(textwrap.wrap(response.choices[0].text, 80, replace_whitespace=False)) + "\n"
        return response
    except openai.InvalidRequestError as e:
        print(f"Invalid request: {str(e)}")
        raise e

def query_func_model(content):
    query = "Could you write a top comment to explain important function steps and it goal.\n" + str(content)
    return _query_model(query)


def build_function_definition():
    """
    Build pyparsing rule for function definition
    :return: pyparsing rule for function definition
    """
    identifier = Word(alphas + nums + '_')
    type_specifier = Word(alphas + nums + '_')
    type_qualifier = oneOf('const volatile')
    storage_class_specifier = oneOf('auto register static extern typedef')
    function_specifier = oneOf('inline')
    type_name = (Optional(type_qualifier) + Optional(type_specifier) + ZeroOrMore(type_qualifier))('type_name')
    declarator = Forward()
    pointer = Optional(Word('*' + '&'))('pointer')
    direct_declarator = identifier
    declarator << (pointer + direct_declarator)
    parameter_type_list = Forward()
    param = Group(Optional(type_qualifier)  + Optional(Word("struct")) + Optional(type_specifier) + Optional(declarator))
    parameter_list = param('parameter') + ZeroOrMore(',' + param)('parameter')
    parameter_type_list << Group(parameter_list + Optional(',' + '...'))('parameter_type_list') | '...'
    
    # return function definition, we used all the above defined rules to define the function definition
    return  (Optional(storage_class_specifier) + Optional(function_specifier) + type_name + declarator + '(' + Optional(parameter_type_list)  + ')' + '{')
    
# define C language syntax for pyparsing


def find_end(content, start):
    """
    Find the end of a C function or struct definition
    :param content: The C code to search
    :param start: The starting index in the content where the function or struct definition begins
     :return: The index of the end of the function or struct definition
    """
    # Initialize a stack to keep track of curly braces
    brace_stack = ['{']
    # Iterate over the characters in the function
    for i, c in enumerate(content[start:]):
        # If we encounter an open curly brace, push it onto the stack
        if c == '{':
            brace_stack.append(c)
        # If we encounter a close curly brace, pop the top element from the stack
        elif c == '}':
            brace_stack.pop()
        # If the stack is empty, we have reached the end of the function
        if len(brace_stack) == 0:
            break

    return start + i + 1

def locate_all(definition, content):
    """
    Locate all instances of a C definition in a given content
    :param definition: The pyparsing definition of the function or struct to search for
    :param content: The C code to search
    :return: A list of tuples, each containing the start and end index of a function or struct definition
    """
    content_located = []
    
    # search for function or struct definitions in the content
    while len(content) > 10:
        definition= locatedExpr(definition)
        try:
            result = definition.parseString(content)[0]
        except Exception:
            # if a function or struct definition is not found, move on to the next block of code
            offset = content.find('\n\n') + 1
            content = content[offset:]
            continue

        start_off = result.locn_start

        end_off = find_end(content, result.locn_end + 30)
        # skip function or struct definitions that are too large
        if end_off - start_off > 4000:
            offset = content.find('\n\n') + 1
            content = content[offset:]
            continue

        content_located.append(content[start_off:end_off])
        offset = end_off + 1
        content = content[offset:]
    return content_located

def main():
    # parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', help='Path to the input file')
    parser.add_argument('output_file', help='Path to the output file')
    args = parser.parse_args()

    # read the input file
    with open(args.input_file, 'r') as f:
        content = f.read()
        
    function_definition = build_function_definition()

    # locate all function definitions in the input file
    functions = locate_all(function_definition, content)
    
    # in a future version, we could also add support for struct definitions
    # skip

    # create a list of all definitions to comment
    definitions = functions 

    # comment each definition
    for definition in definitions:
        # send definition to OpenAI API
        description = query_func_model(definition)
        replace = description + definition
        content = content.replace(definition, replace) 
        print(replace)
        

    # write refactored definitions to the output file
    with open(args.output_file, 'w') as f:
        f.write(content)

if __name__ == '__main__':
    main()
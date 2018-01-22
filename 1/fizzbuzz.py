#!/usr/bin/python 

import argparse
import sys

# CS 352 Fizzbuzz Assignment Skeleton
#
# (c) 2018 R. P. Martin under the GPL version 2 license 

def main():
    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 FizzBuzz')
    parser.add_argument('-s','--start', help='Starting Value', required=True)
    parser.add_argument('-e','--end', help='Ending Value', required=True)

    # parse the input 
    args = vars(parser.parse_args())
    start = int(args['start'])
    end = int(args['end'])

    print("CS 352 fizzbuzz, start at %d, end at %d " % (start,end) )

    # For every number from the start to the end (inclusive):
    
    # if the number is divisible by 3, print "Fizz" (newline) 
    # if the number is divisible by 5, print "Buzz" (newline)
    # if the number is divisible by both 3 and 5, print "FizzBuzz" (newline)
    # if the number is neither divisible by 3 or 5, print the sum of all the previous numbers
    # which have been printed, starting with zero. (newline) 
    
    # your code goes here.
    

    total = 0
    for i in range(start, end+1):
        if i%15 == 0:
            print("FizzBuzz")
        elif i%5 == 0:
            print("Buzz")
        elif i%3 == 0:
            print("Fizz")
        else:
            print(total)
            total+=i

            
# create a main function in Python
if __name__ == "__main__":
    main()



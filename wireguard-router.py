#!/usr/bin/env python3
import sys
from ObjectGenerator import ObjectGenerator

def main():
    try:
        r = ObjectGenerator(sys.argv[1])
    except:
        r = ObjectGenerator()
    exit()


if __name__ == '__main__':
    main()
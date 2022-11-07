from utils import exec_cmd, exec_cmd_bash
import argparse


parser = argparse.ArgumentParser(description='Optional app description')

parser.add_argument('--ip', type=str, required=True)


args = parser.parse_args()

print(args.ip)